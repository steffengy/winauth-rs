//! Hyper Windows Authentication "Middleware"
extern crate base64;
extern crate bytes;
#[macro_use]
extern crate futures;
extern crate hyper;
extern crate winauth;

use std::borrow::Cow;
use std::fmt;
use std::str;
use std::sync::Arc;
use futures::{Async, Future, Poll, Stream};
use hyper::client;
use hyper::header;

#[derive(Copy, Clone, Debug, PartialEq)]
enum Scheme {
    Ntlm,
}

#[derive(Clone, PartialEq, Debug)]
struct WWWAuthenticate(Vec<(Scheme, Option<Vec<u8>>)>);

impl header::Header for WWWAuthenticate {
    fn header_name() -> &'static str {
        "WWW-Authenticate"
    }

    fn parse_header(raw: &header::Raw) -> hyper::Result<WWWAuthenticate> {
        let mut pairs = Vec::with_capacity(raw.len());
        for line in raw {
            let header = try!(str::from_utf8(line));
            let scheme = "NTLM";
            if header.starts_with(scheme) {
                if scheme.len() + 1 < line.len() {
                    let bytes = match base64::decode(&header[scheme.len()+1..]) {
                        Err(_) => return Err(hyper::Error::Header),
                        Ok(x) => x,
                    };
                    pairs.push((Scheme::Ntlm, Some(bytes)));
                }  else {
                    pairs.push((Scheme::Ntlm, None))
                }
            }
        }
        if pairs.is_empty() {
            Err(hyper::Error::Header)
        } else {
            Ok(WWWAuthenticate(pairs))
        }
    }

    fn fmt_header(&self, f: &mut ::header::Formatter) -> fmt::Result {
        f.fmt_line(self)
    }
}

impl fmt::Display for WWWAuthenticate {
    fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!();
    }
}

/// The authentication method to use to authenticate against a server
#[allow(non_camel_case_types)]
pub enum AuthMethod {
    /// NTLMv2 authentication
    NTLMv2(Cow<'static, str>, Cow<'static, str>),
    /// Single sign on using the current/local credentials (windows-only)
    /// TODO: This should actually use Negotiate, currently NTLMv2
    #[cfg(windows)]
    SSPI_SSO
}

struct Inner<T> {
    service: T,
    auth: AuthMethod,
}

/// A client that performs HTTP-based NTLM authentication, when requested
/// on an underlying request
/// This requires `keep-alive` or HTTP/1.1 (persistent connections) to be used
/// for the handshake.
pub struct WinAuthClient<T: client::Service> {
    inner: Arc<Inner<T>>,
}

impl<'a, T> WinAuthClient<T> 
    where T: client::Service<Response=hyper::Response> + 'static 
{
    pub fn new(service: T, auth: AuthMethod) -> WinAuthClient<T> {
        WinAuthClient { 
            inner: Arc::new(Inner { service, auth })
        }
    }
}

enum InnerState<F> {
    Initial(futures::stream::Concat2<hyper::Body>),
    Chunks(bytes::Bytes),
    Req(bytes::Bytes, F),
    Done(Option<hyper::Response>),
}

pub struct WinAuthFuture<T: client::Service> {
    inner: Arc<Inner<T>>,
    method: hyper::Method,
    uri: hyper::Uri,
    vers: hyper::HttpVersion,
    headers: hyper::Headers,
    state: InnerState<T::Future>,
    
    winauth: Option<Box<winauth::NextBytes>>,
}

impl<T> Future for WinAuthFuture<T>
    where T: client::Service<Request = hyper::Request, Response = hyper::Response, Error = hyper::Error>
{
    type Item = T::Response;
    type Error = T::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            self.state = match self.state {
                InnerState::Initial(ref mut body) => {
                    // TODO: hopefully in the future the underlying `Bytes` object is 
                    // directly accessible and clonable (data is duplicated 3x in sum)
                    let chunks = bytes::Bytes::from(try_ready!(body.poll()).to_vec());
                    InnerState::Chunks(chunks)
                }
                InnerState::Chunks(ref mut chunks) => {
                    let mut req: hyper::Request<hyper::Body> = hyper::Request::new(
                        self.method.clone(), self.uri.clone()
                    );
                    req.set_version(self.vers);
                    *req.headers_mut() = self.headers.clone();
                    // TODO: a really ugly workaround to atleast not duplicate on each request
                    req.set_body(hyper::Body::from(chunks.clone()));
                    InnerState::Req(chunks.clone(), self.inner.service.call(req))
                }
                InnerState::Req(ref mut chunks, ref mut req) => {
                    let resp = try_ready!(req.poll());
                    let mut done = true;
                    if let Some(header) = resp.headers().get::<WWWAuthenticate>() {
                        // check if NTLM authentication is supported/requested
                        let elem = header.0.iter()
                                           .filter(|&&(x, _)| x == Scheme::Ntlm)
                                           .map(|&(_, ref x)| x)
                                           .nth(0);

                        if let Some(elem) = elem {
                            // check if this is the initial request (not containing any bytes)
                            if elem.is_none() {
                                assert!(self.winauth.is_none());
                                let winauth = match self.inner.auth {
                                    #[cfg(windows)]
                                    AuthMethod::SSPI_SSO => {
                                        Box::new(winauth::windows::NtlmSspiBuilder::new().build()?)
                                    }
                                    AuthMethod::NTLMv2(_, _) => {
                                        // Box::new(winauth::NtlmV2ClientBuilder::build(
                                        unimplemented!()
                                    }
                                };
                                self.winauth = Some(winauth);
                            }
                            let next = self.winauth.as_mut().unwrap()
                                           .next_bytes(elem.as_ref().map(|x| &**x))?;

                            if let Some(next) = next {
                                let encoded = base64::encode(&next);
                                self.headers.set_raw("Authorization", format!("NTLM {}", encoded));
                                done = false;
                            }
                        }
                    }
                    if done {
                        InnerState::Done(Some(resp))
                    } else {
                        InnerState::Chunks(chunks.clone())
                    }
                }
                InnerState::Done(ref mut ret) => {
                    return Ok(Async::Ready(ret.take().unwrap()));
                }
            };
        }
    }
}

impl<T> client::Service for WinAuthClient<T> 
    where T: client::Service<Request=hyper::Request, Response=hyper::Response, Error=hyper::Error> + 'static,
{
    type Request = T::Request;
    type Response = T::Response;
    type Error = T::Error;
    type Future = WinAuthFuture<T>;

    fn call(&self, req: Self::Request) -> Self::Future {
        let (method, uri, vers, headers, body) = req.deconstruct();
        WinAuthFuture {
            inner: self.inner.clone(),
            method,
            uri,
            vers,
            headers,
            state: InnerState::Initial(body.concat2()),
            winauth: None,
        }
    }
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    extern crate tokio_core;

    use std::str;
    use futures::{Future, Stream};
    use hyper::{Method, Request};
    use hyper::client::{Client, Service};
    use self::tokio_core::reactor::Core;
    use super::{AuthMethod, WinAuthClient};

    #[test]
    fn basic_test() {
        let mut core = Core::new().unwrap();
        let client = Client::new(&core.handle());
        let wrapped = WinAuthClient::new(client, AuthMethod::SSPI_SSO);
        let req = Request::new(Method::Get, "http://localhost/index.html".parse().unwrap());
        let work = wrapped.call(req).and_then(|res| {
            println!("Response: {}", res.status());
            res.body().concat2()
        });
        let res = core.run(work).unwrap();
        let body = str::from_utf8(res.as_ref());
        assert_eq!(body, Ok("hello world"));
    }
}
