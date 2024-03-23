//! A hyper server that authenticates an user initially and then keeps the auth credentials
//! as part of a "session" through a cookie and in-memory store
//! can be adopted to database-based session management

use hyper::{Request, Response};
use hyper::body::{Body, Bytes};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full, Empty};
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};


use winauth::http::Authenticator;

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(windows)] {


// A dummy not necessarily best-practice way to fairly easily get a connection specific context
struct ConnCtx {
    auth: Arc<Mutex<AuthContext>>,
    sess: Arc<Mutex<HashMap<String, String>>>
}

impl ConnCtx {
    fn handle_conn(&self, req: Request<hyper::body::Incoming>) -> impl Future<Output=Result<Response<BoxBody<Bytes, Infallible>>, Infallible>>  {
        let mut inner = Arc::clone(&self.auth);
        let mut sess = Arc::clone(&self.sess);

        async move {
           // Handle requests that work with sessions or might not need auth first
           if !req.uri().path().starts_with("/auth/windows") {
                // FIXME The cookie handling here is very minimal for demo purposes. This wont work in production!
                let content = match req.headers().get("cookie").map(|x| x.to_str().unwrap()) {
                    Some(ref val) => {
                        let store = sess.lock().unwrap();
                        let user = store.get(val.split("=").nth(1).unwrap()).unwrap();
                        format!("Welcome Back, {}", user)
                    }
                    None => "Not logged in. Go to /auth/windows".to_owned(),
                };

                return Ok(Response::new(Full::new(Bytes::from(content)).boxed()));
            }

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
            let cookie_name = generate_INSECURE_random_string();
            println!("Got auth request from user {}. Setting cookie {}", username, cookie_name);
            sess.lock().unwrap().insert(cookie_name.clone(), username.to_owned());
            let builder = Response::builder()
                .header("Set-Cookie", format!("session={};path=/", cookie_name)); // FIXME Use the cookie crate for this in production!
            Ok(builder.body(Full::new(Bytes::from(format!("Hello {}", username))).boxed()).unwrap())
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
            let ctx = ConnCtx { 
                auth: Arc::new(Mutex::new(AuthContext::None)),
                sess: Arc::new(Mutex::new(HashMap::default())),
            };

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

// FIXME This is just for demonstration purposes.
// Use a cryptographically secure PRNG (e.g. rand's StdRng)!
fn generate_INSECURE_random_string() -> String {
    println!("WARNING: DO NOT USE THIS DUMMY COOKIE GENERATOR IN PRODUCTION");
    "abcdefghHIGHTLYsecureCOOKIE".to_owned()
}
        
    } // WINDOWS
    else {
        fn main() {
            panic!("only windows supported");
        }
    }
}
