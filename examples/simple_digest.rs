use digest_auth::{AuthContext, HttpMethod, WwwAuthenticateHeader};
use futures::stream::StreamExt;
use http::Extensions;
use reqwest::{Request, Response};
use reqwest_eventsource::{CannotCloneRequestError, Event, RequestBuilderExt};
use reqwest_middleware::{Middleware, Next};

pub struct DigestAuth {
    username: String,
    password: String,
}

impl DigestAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

#[async_trait::async_trait]
impl Middleware for DigestAuth {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response, reqwest_middleware::Error> {
        // Send first request
        let res = next
            .clone()
            .run(
                req.try_clone().ok_or_else(|| {
                    reqwest_middleware::Error::Middleware(CannotCloneRequestError.into())
                })?,
                extensions,
            )
            .await?;
        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(response) = res
                .headers()
                .get("WWW-Authenticate")
                .and_then(|header| header.to_str().ok())
                .filter(|str| str.starts_with("Digest "))
                .and_then(|header| WwwAuthenticateHeader::parse(header).ok())
                .and_then(|mut challenge| {
                    challenge
                        .respond(&AuthContext::new_with_method(
                            &self.username,
                            &self.password,
                            &req.url().path().to_string(),
                            None::<&[u8]>,
                            HttpMethod::from(req.method().as_str()),
                        ))
                        .ok()
                })
                .and_then(|response| response.to_header_string().parse().ok())
            {
                req.headers_mut().insert("Authorization", response);
                return next.run(req, extensions).await;
            }
        }

        Ok(res)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with(DigestAuth::new("admin", "admin"))
        .build();
    let mut es = client
        .get("http://localhost:8000/events_auth")
        .eventsource()?;
    while let Some(event) = es.next().await {
        match event {
            Ok(Event::Open) => println!("Connection Open!"),
            Ok(Event::Message(message)) => println!("Message: {:#?}", message),
            Err(err) => {
                println!("Error: {}", err);
                // es.close();
            }
        }
    }
    Ok(())
}
