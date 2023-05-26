#[cfg(feature = "fetch")]
use rocket::tokio::sync::Mutex;
#[cfg(feature = "fetch")]
use std::sync::Arc;

#[cfg(feature = "fetch")]
use super::claims::{Claims, UserInClaims};

#[cfg(feature = "fetch")]
pub struct Fetch {
    pub client: Arc<Mutex<reqwest::Client>>,
}

#[cfg(feature = "fetch")]
impl Fetch {
    pub fn new() -> Self {
        let client = Arc::new(Mutex::new(reqwest::Client::new()));
        Fetch { client }
    }

    pub async fn robot_token() -> Result<String, jsonwebtoken::errors::Error> {
        return Claims::from(UserInClaims::default()).enconde_for_robot();
    }
}
