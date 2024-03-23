//! A minimal hyper server example
use hyper::{Request, Response};
use hyper::body::{Body, Bytes};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full, Empty};
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::future::Future;
use std::sync::{Arc, Mutex};


use winauth::http::Authenticator;

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(windows)] {


// A dummy not necessarily best-practice way to fairly easily get a connection specific context
struct ConnCtx(Arc<Mutex<AuthContext>>);
impl ConnCtx {
    fn handle_conn(&self, req: Request<hyper::body::Incoming>) -> impl Future<Output=Result<Response<BoxBody<Bytes, Infallible>>, Infallible>>  {
        let mut inner = Arc::clone(&self.0);

        async move {
            let mut inner = inner.lock().unwrap();

            // Perform authentication (at most once per connection) for Windows
            if let AuthContext::None = *inner {
                let sspi = winauth::windows::NtlmSspiBuilder::new()
                    .inbound()
                    .build()
                    .unwrap();
                    *inner = AuthContext::Pending(sspi);
            }
            if let AuthContext::Pending(ref mut sspi) = *inner {
                let fetch_header = |header_name| Ok(
                    req.headers().get(header_name).map(|x| x.to_str()).transpose()?
                );
                *inner = match sspi.http_incoming_auth(fetch_header).unwrap() {
                    // This cannot happen for the server-side
                    winauth::http::AuthState::NotRequested => unreachable!(),
                    // Pass along a http-response to the client, if needed for auth.
                    // The client will retry the request and include additional auth data.
                    winauth::http::AuthState::Response(ref resp) => {
                        let mut builder = hyper::Response::builder();
                        for (k, v) in &resp.headers {
                            builder = builder.header(*k, v);
                        }
                        builder = builder.status(resp.status_code);
                        return Ok(builder.body(Empty::new().boxed()).unwrap())
                    },
                    // We finally have performed enough requests and authenticated successfully
                    // Get the username into the client name
                    winauth::http::AuthState::Success => AuthContext::Authenticated(sspi.client_identity().unwrap()),
                };
            }

            // Authentication was successful. Store the username in a dummy session store (as we would in a database)
            let username = inner.username();
            Ok(Response::new(Full::new(Bytes::from(format!("Hello {}", username))).boxed()))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = "127.0.0.1:3000";
    println!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            let ctx = ConnCtx(Arc::new(Mutex::new(AuthContext::None)));

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |a| ctx.handle_conn(a)))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

/// State of windows authentication for the currently served HTTP connection
/// Ensures auth is performed at most once per connection.
enum AuthContext {
    /// We have not yet needed to authenticate for this connection
    None,
    /// The authentication process for this connection is pending
    Pending(winauth::windows::NtlmSspi),
    /// We are successfully authenticated as (username).
    Authenticated(String),
}

impl AuthContext {
    /// Return the username associated with this context, or panic.
    fn username(&self) -> &str {
        match *self {
            AuthContext::None | AuthContext::Pending(_) => panic!("This should not be reachable"),
            AuthContext::Authenticated(ref user) => &user,
        }
    }
}
        
    } // WINDOWS
    else {
        fn main() {
            panic!("only windows supported");
        }
    }
}
