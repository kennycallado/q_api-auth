#![allow(unused)]

use rocket::{http::Status, State};
use serde::{Deserialize, Serialize};

use crate::app::providers::config_getter::ConfigGetter;

#[cfg(feature = "fetch")]
use crate::app::providers::services::fetch::Fetch;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubToken {
    pub id: i32,
    pub user_id: i32,
    pub fcm_token: Option<String>,
    pub web_token: Option<rocket::serde::json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubNewToken {
    pub user_id: i32,
    pub fcm_token: Option<String>,
    pub web_token: Option<rocket::serde::json::Value>,
}

#[cfg(feature = "fetch")]
impl PubToken {
    pub async fn init_user(fetch: &State<Fetch>, user_id: i32) -> Result<Self, Status> {
        let new_token = PubNewToken {
            user_id,
            fcm_token: None,
            web_token: None,
        };

        let robot_token = match Fetch::robot_token().await {
            Ok(token) => token,
            Err(_) => return Err(Status::InternalServerError),
        };

        let message_url = ConfigGetter::get_entity_url("message")
            .unwrap_or("http://localhost:8005/api/v1/messaging/".to_string())
            + "token/";

        let res;
        {
            let client = fetch.client.lock().await;
            res = client
                .post(message_url)
                .header("Accept", "application/json")
                .header("Authorization", robot_token)
                .header("Content-Type", "application/json")
                .json(&new_token)
                .send()
                .await;
        }

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
