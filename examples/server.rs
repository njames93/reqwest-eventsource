use digest_auth::{AuthContext, AuthorizationHeader, HttpMethod};
use rocket::http::{Header, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::content::RawHtml;
use rocket::response::stream::{Event, EventStream};
use rocket::response::Responder;
use rocket::tokio::time::{self, Duration};
use rocket::{catch, catchers, get, launch, routes, Response};
use std::time::SystemTime;

const USER_NAME: &'static str = "admin";
const PASSWORD: &'static str = "admin";
pub struct DigestUser(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for DigestUser {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let header_val = match req.headers().get_one("Authorization") {
            Some(h) => h,
            None => return Outcome::Error((Status::Unauthorized, ())),
        };

        let auth_header = match AuthorizationHeader::parse(header_val) {
            Ok(h) => h,
            Err(_) => return Outcome::Error((Status::Unauthorized, ())),
        };

        if auth_header.username != USER_NAME {
            return Outcome::Error((Status::Unauthorized, ()));
        }
        let uri = auth_header.uri.clone();
        let method = HttpMethod::from(req.method().as_str());

        let ctx = AuthContext::new_with_method(
            &auth_header.username,
            PASSWORD,
            &uri,
            None::<&[u8]>,
            method,
        );

        let mut computed = auth_header.clone();
        computed.digest(&ctx);

        if computed.response == auth_header.response {
            Outcome::Success(DigestUser(auth_header.username))
        } else {
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

struct DigestChallengeResponder;

impl<'r> Responder<'r, 'static> for DigestChallengeResponder {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let header_value =
            r#"Digest realm="Restricted", qop="auth", nonce=INSECURE_NONCE", opaque="opaque""#;

        Response::build()
            .status(Status::Unauthorized)
            .header(Header::new("WWW-Authenticate", header_value))
            .ok()
    }
}

#[catch(401)]
fn unauthorized() -> DigestChallengeResponder {
    DigestChallengeResponder
}

pub struct LastEventId(pub usize);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for LastEventId {
    type Error = std::num::ParseIntError;
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(id) = req.headers().get("Last-Event-ID").next() {
            if id.is_empty() {
                Outcome::Success(LastEventId(0))
            } else {
                match id.parse() {
                    Ok(id) => Outcome::Success(LastEventId(id)),
                    Err(err) => Outcome::Error((Status::BadRequest, err)),
                }
            }
        } else {
            Outcome::Success(LastEventId(0))
        }
    }
}

#[get("/events")]
fn events(id: LastEventId) -> EventStream![] {
    let mut id = id.0;
    let mut interval = time::interval(Duration::from_secs(2));
    EventStream! {
        loop {
            interval.tick().await;
            let unix_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            id += 1;
            yield Event::data(unix_time.to_string()).id(id.to_string());
        }
    }
}

#[get("/events_auth")]
fn events_auth(id: LastEventId, user: DigestUser) -> EventStream![] {
    let _ = user;
    let mut id = id.0;
    let mut interval = time::interval(Duration::from_secs(2));
    EventStream! {
        loop {
            interval.tick().await;
            let unix_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            id += 1;
            yield Event::data(unix_time.to_string()).id(id.to_string());
        }
    }
}

#[get("/")]
fn index() -> RawHtml<&'static str> {
    RawHtml(
        r#"
Open Console
<script>
    const es = new EventSource("http://localhost:8000/events");
    es.onopen = () => console.log("Connection Open!");
    es.onmessage = (e) => console.log("Message:", e);
    es.onerror = (e) => {
        console.log("Error:", e);
    };
</script>
"#,
    )
}

#[get("/auth")]
fn index_auth() -> RawHtml<&'static str> {
    RawHtml(
        r#"
Open Console
<script>
    const es = new EventSource("http://localhost:8000/events_auth");
    es.onopen = () => console.log("Connection Open!");
    es.onmessage = (e) => console.log("Message:", e);
    es.onerror = (e) => {
        console.log("Error:", e);
    };
</script>
"#,
    )
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![events, index, events_auth, index_auth])
        .register("/", catchers![unauthorized])
}
