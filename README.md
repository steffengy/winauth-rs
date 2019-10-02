WinAuth
=======

[![Build Status](https://dev.azure.com/steffengy/winauth-rs/_apis/build/status/winauth-rs-CI?branchName=master)](https://dev.azure.com/steffengy/winauth-rs/_build/latest?definitionId=1&branchName=master)
[![Documentation](https://docs.rs/winauth/badge.svg)](https://docs.rs/winauth)  

The intention of this crate is to provide support to authenticate against windows systems using
the builtin windows authentication.

This currently provides support for windows authentication using the following protocols:
- NTLMv2

A quick and easy way one liner to get going is as follows:

    extern crate winauth;
    use crate::winauth::http::Authenticator;
    
    fn main() {
        let mut url : String = r##"http://localhost:54999/API/API?ACTION=ViewActiveDirectoryProfile&AD_ENTRY="##.to_string();
        url = [
               url.to_string(),
               urlencoding::encode(r##"{"mail":"jsmith"}"##).to_string(),
        ].join("");        
        let mut res = winauth::perform_ntlm_request!(reqwest::Method::GET, &url, builder, {
            builder = builder.header("foo", "bar");
        });
        println!("Response {:?}", res);
        println!("Body: {:?}", res.text().unwrap());
    }

