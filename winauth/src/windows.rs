//! Windows-Native NTLM functionalities (including SSO capabilities)
//!
//! This is mainly used to verify our implementation
extern crate kernel32;
extern crate secur32;
extern crate winapi;

use std::io;
use std::mem;
use std::ptr;
use std::slice;
use NextBytes;

static NTLM_PROVIDER: &'static [u8] = b"NTLM\0";

const INIT_REQUEST_FLAGS: winapi::c_ulong =
    winapi::ISC_REQ_CONFIDENTIALITY |
    winapi::ISC_REQ_INTEGRITY |
    winapi::ISC_REQ_REPLAY_DETECT |
    winapi::ISC_REQ_SEQUENCE_DETECT |
    winapi::ISC_REQ_CONNECTION |
    winapi::ISC_REQ_DELEGATE |
    winapi::ISC_REQ_USE_SESSION_KEY |
    winapi::ISC_REQ_ALLOCATE_MEMORY;

const ACCEPT_REQUEST_FLAGS: winapi::c_ulong =
    winapi::ASC_REQ_CONFIDENTIALITY |
    winapi::ASC_REQ_INTEGRITY |
    winapi::ASC_REQ_REPLAY_DETECT |
    winapi::ASC_REQ_SEQUENCE_DETECT |
    winapi::ASC_REQ_CONNECTION |
    winapi::ASC_REQ_DELEGATE |
    winapi::ASC_REQ_USE_SESSION_KEY |
    winapi::ASC_REQ_ALLOCATE_MEMORY;

/// Builder for `NtlmSspi` which provides configuration for it
pub struct NtlmSspiBuilder {
    outbound: bool,
    target_spn: Option<Vec<u16>>,
    channel_bindings: Option<Vec<u8>>,
}

impl NtlmSspiBuilder {
    pub fn new() -> NtlmSspiBuilder {
        NtlmSspiBuilder {
            outbound: true,
            target_spn: None,
            channel_bindings: None,
        }
    }

    /// Outbound Mode = Client Mode (authenticate against a server)
    pub fn outbound(mut self) -> NtlmSspiBuilder {
        self.outbound = true;
        self
    }

    /// Inbound Mode = Server Mode (accept authentication from a client)
    pub fn inbound(mut self) -> NtlmSspiBuilder {
        self.outbound = false;
        self
    }

    /// Set a target SPN. This requires a client to specify that it intends to identify against this SPN.
    /// This limits replay attacks against the same server/service, since the SPN has to match.
    pub fn target_spn(mut self, spn: &str) -> NtlmSspiBuilder {
        self.target_spn = Some(spn.encode_utf16().chain(Some(0)).collect());
        self
    }

    /// Set a channel binding. This limits client requests to the same channel.
    /// This means e.g. that the authentication can only be successful over the same TLS connection.
    pub fn channel_bindings(mut self, data: &[u8]) -> NtlmSspiBuilder {
        self.channel_bindings = Some(super::make_sec_channel_bindings(data, false));
        self
    }

    pub fn build(self) -> Result<NtlmSspi, io::Error> {
        NtlmSspi::new(self)
    }
}

/// Either perform single-sign-on using NTLM (performing a login with the current windows identity)
/// or validate incoming auth requests
///
/// # Warning
/// Using `target_spn` or/and `channel_bindings` is RECOMMENDED for security purposes!
pub struct NtlmSspi {
    builder: NtlmSspiBuilder,
    ctx: Option<SecurityContext>,
    cred: NtlmCred,
}

impl NtlmSspi {
    fn new(builder: NtlmSspiBuilder) -> Result<NtlmSspi, io::Error> {
        unsafe {
            let mut handle = mem::zeroed();
            let direction = if builder.outbound {
                winapi::SECPKG_CRED_OUTBOUND
            } else {
                winapi::SECPKG_CRED_INBOUND
            };
            // accquire the initial token (negotiate for either kerberos or NTLM)
            let ret = secur32::AcquireCredentialsHandleA(ptr::null_mut(),
                                                         NTLM_PROVIDER.as_ptr() as *mut i8,
                                                         direction,
                                                         ptr::null_mut(),
                                                         ptr::null_mut(),
                                                         None,
                                                         ptr::null_mut(),
                                                         &mut handle,
                                                         ptr::null_mut());
            let cred = match ret {
                winapi::SEC_E_OK => NtlmCred(handle),
                err => return Err(io::Error::from_raw_os_error(err as i32)),
            };

            let sso = NtlmSspi {
                builder: builder,
                ctx: None,
                cred: cred,
            };
    
            Ok(sso)
        }
    }
}

impl NextBytes for NtlmSspi {
    fn next_bytes(&mut self, in_bytes: Option<&[u8]>) -> Result<Option<Vec<u8>>, io::Error> {
        unsafe {
            let mut ctx = None;

            let (ctx_ptr, ctx_ptr_in) = if let Some(ref mut ctx_ptr) = self.ctx {
                (&mut ctx_ptr.0 as *mut _, &mut ctx_ptr.0 as *mut _)
            } else {
                ctx = Some(mem::zeroed());
                (ctx.as_mut().unwrap() as *mut _, ptr::null_mut())
            };

            let has_in_bytes = in_bytes.is_some();
            let mut inbuf = [secbuf(winapi::SECBUFFER_EMPTY, None), 
                             secbuf(winapi::SECBUFFER_TOKEN, in_bytes.as_ref().map(|x| x.as_ref()))];
            if let Some(ref binding) = self.builder.channel_bindings {
                inbuf[0] = secbuf(winapi::SECBUFFER_CHANNEL_BINDINGS, Some(binding));
            }
            let mut inbuf_desc = secbuf_desc(&mut inbuf);

            let inbuf_ptr = if has_in_bytes {
                &mut inbuf_desc as *mut _
            } else {
                ptr::null_mut()
            };

            let inbuf_ptr = &mut inbuf_desc as *mut _;

            let mut outbuf = [secbuf(winapi::SECBUFFER_TOKEN, None)];
            let mut outbuf_desc = secbuf_desc(&mut outbuf);
            let target_name_ptr = self.builder.target_spn.as_mut().map(|x| x.as_mut_ptr()).unwrap_or(ptr::null_mut());
            // create a token message
            let mut attrs = 0u32;
            let ret = if self.builder.outbound {
                secur32::InitializeSecurityContextW(&mut self.cred.0,
                                                    ctx_ptr_in,
                                                    target_name_ptr,
                                                    INIT_REQUEST_FLAGS,
                                                    0,
                                                    winapi::SECURITY_NETWORK_DREP,
                                                    inbuf_ptr,
                                                    0,
                                                    ctx_ptr,
                                                    &mut outbuf_desc,
                                                    &mut attrs,
                                                    ptr::null_mut())
            } else {
                secur32::AcceptSecurityContext(&mut self.cred.0,
                                               ctx_ptr_in,
                                               inbuf_ptr,
                                               ACCEPT_REQUEST_FLAGS,
                                               winapi::SECURITY_NETWORK_DREP,
                                               ctx_ptr,
                                               &mut outbuf_desc,
                                               &mut attrs,
                                               ptr::null_mut())
            };

            match ret {
                winapi::SEC_E_OK | winapi::SEC_I_CONTINUE_NEEDED => {
                    if let Some(new_ctx) = ctx {
                        self.ctx = Some(SecurityContext(new_ctx));
                    }
                    if outbuf[0].cbBuffer > 0 {
                        Ok(Some(ContextBuffer(outbuf[0]).as_ref().to_vec()))
                    } else {
                        assert_eq!(ret, winapi::SEC_E_OK);
                        Ok(None)
                    }
                },
                err => Err(io::Error::from_raw_os_error(err)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use super::NtlmSspiBuilder;
    use {NextBytes, NtlmV2ClientBuilder};

    /// check if we can authenticate us against us (using SSPI)
    #[test]
    fn test_winapi_sspi_ntlm_auth() {
        let mut client = NtlmSspiBuilder::new().outbound().build().unwrap();
        let mut server = NtlmSspiBuilder::new().inbound().build().unwrap();
        let mut next_client_bytes: Option<Vec<u8>> = None;
        let mut next_server_bytes: Option<Vec<u8>>;

        loop {
            next_server_bytes = {
                let client_bytes = next_client_bytes.as_ref().map(|x| x.as_slice());
                client.next_bytes(client_bytes).unwrap()
            };
            let server_bytes = next_server_bytes.as_ref().map(|x| x.as_slice());
            next_client_bytes = server.next_bytes(server_bytes).unwrap();
            if next_client_bytes.is_none() {
                break;
            }
        }
    }

    fn get_auth_creds() -> (Option<String>, String, String) {
        (
            None, 
            env::var("USERNAME").unwrap(),
            env::var("TEST_PW").unwrap()
        )
    }

    #[test]
    fn test_ntlm_insecure_rust_client_against_winapi() {
        let mut server = NtlmSspiBuilder::new().inbound().build().unwrap();

        let creds = get_auth_creds();
        let mut client = NtlmV2ClientBuilder::new().build(creds.0, creds.1, creds.2);
        let init_bytes = client.next_bytes(None).unwrap().unwrap();
        let challenge_bytes = server.next_bytes(Some(&init_bytes)).unwrap().unwrap();
        let authenticate_bytes = client.next_bytes(Some(&challenge_bytes)).unwrap().unwrap();
        assert!(server.next_bytes(Some(&authenticate_bytes)).unwrap().is_none());
    }

    #[test]
    fn test_ntlm_channel_bindings_winapi_server() {
        let dbg_bindings = b"\x74\x6c\x73\x2d\x73\x65\x72\x76\x65\x72\x2d\x65\x6e\x64\x2d\x70\x6f\x69\x6e\x74\x3a\xea\x05\xfe\xfe\xcc\x6b\x0b\xd5\x71\xdb\xbc\x5b\xaa\x3e\xd4\x53\x86\xd0\x44\x68\x35\xf7\xb7\x4c\x85\x62\x1b\x99\x83\x47\x5f\x95";
        
        let creds = get_auth_creds();

        let mut client = NtlmV2ClientBuilder::new()
            .channel_bindings(dbg_bindings)
            .build(creds.0, creds.1,creds.2);
        let mut server = NtlmSspiBuilder::new().inbound()
            .channel_bindings(dbg_bindings)
            .build().unwrap();

        let init_bytes = client.next_bytes(None).unwrap().unwrap();
        let challenge_bytes = server.next_bytes(Some(&init_bytes)).unwrap().unwrap();
        let authenticate_bytes = client.next_bytes(Some(&challenge_bytes)).unwrap().unwrap();
        assert!(server.next_bytes(Some(&authenticate_bytes)).unwrap().is_none());
    }

    #[test]
    fn test_ntlm_target_spn_against_winapi() {
        let creds = get_auth_creds();

        let mut client = NtlmV2ClientBuilder::new()
            .target_spn("test-pc")
            .build(creds.0, creds.1,creds.2);
        let mut server = NtlmSspiBuilder::new().inbound()
            .build().unwrap();

        // TODO: for CI register an SPN so that this test fails (since the SPN should match)

        let init_bytes = client.next_bytes(None).unwrap().unwrap();
        let challenge_bytes = server.next_bytes(Some(&init_bytes)).unwrap().unwrap();
        let authenticate_bytes = client.next_bytes(Some(&challenge_bytes)).unwrap().unwrap();
        assert!(server.next_bytes(Some(&authenticate_bytes)).unwrap().is_none());
    }
}


// some helper stuff imported frm schannel.rs
struct NtlmCred(winapi::CredHandle);

impl Drop for NtlmCred {
    fn drop(&mut self) {
        unsafe {
            secur32::FreeCredentialsHandle(&mut self.0);
        }
    }
}

struct SecurityContext(winapi::CtxtHandle);

impl Drop for SecurityContext {
    fn drop(&mut self) {
        unsafe {
            secur32::DeleteSecurityContext(&mut self.0);
        }
    }
}

/// A managed windows-allocated buffer, that dereferences into &[u8]
pub struct ContextBuffer(winapi::SecBuffer);

impl Drop for ContextBuffer {
    fn drop(&mut self) {
        unsafe {
            secur32::FreeContextBuffer(self.0.pvBuffer);
        }
    }
}

impl AsRef<[u8]> for ContextBuffer {
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.0.pvBuffer as *const _, self.0.cbBuffer as usize) }
    }
}


unsafe fn secbuf(buftype: winapi::c_ulong,
                    bytes: Option<&[u8]>) -> winapi::SecBuffer {
    let (ptr, len) = match bytes {
        Some(bytes) => (bytes.as_ptr(), bytes.len() as winapi::c_ulong),
        None => (ptr::null(), 0),
    };
    winapi::SecBuffer {
        BufferType: buftype,
        cbBuffer: len,
        pvBuffer: ptr as *mut winapi::c_void,
    }
}

unsafe fn secbuf_desc(bufs: &mut [winapi::SecBuffer]) -> winapi::SecBufferDesc {
    winapi::SecBufferDesc {
        ulVersion: winapi::SECBUFFER_VERSION,
        cBuffers: bufs.len() as winapi::c_ulong,
        pBuffers: bufs.as_mut_ptr(),
    }
}
