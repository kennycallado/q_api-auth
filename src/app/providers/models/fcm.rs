#![allow(unused)]

use rocket::{http::Status, State};
use serde::{Deserialize, Serialize};

use crate::app::providers::config_getter::ConfigGetter;

#[cfg(feature = "fetch")]
use crate::app::providers::services::fetch::Fetch;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubFcmToken {
    pub id: i32,
    pub user_id: i32,
    pub token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubNewFcmToken {
    pub user_id: i32,
    pub token: Option<String>,
}

#[cfg(feature = "fetch")]
impl PubFcmToken {
    pub async fn init_user(fetch: &State<Fetch>, user_id: i32) -> Result<Self, Status> {
        let new_token = PubNewFcmToken {
            user_id,
            token: None,
        };

        let robot_token = match Fetch::robot_token().await {
            Ok(token) => token,
            Err(_) => return Err(Status::InternalServerError),
        };

        let fcm_url = ConfigGetter::get_entity_url("fcm")
            .unwrap_or("http://localhost:8005/api/v1/fcm/".to_string())
            + "token";

        let client = fetch.client.lock().await;
        let res = client
            .post(fcm_url)
            .header("Accept", "application/json")
            .header("Authorization", robot_token)
            .header("Content-Type", "application/json")
            .json(&new_token)
            .send()
            .await;

        match res {
            Ok(res) => {
                if !res.status().is_success() {
                    return Err(Status::from_code(res.status().as_u16()).unwrap());
                }

                Ok(res.json::<Self>().await.unwrap())
            }
            Err(_) => Err(Status::InternalServerError),
        }
    }
}
