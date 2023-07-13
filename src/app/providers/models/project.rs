#![allow(unused)]

use rocket::{http::Status, State};
use serde::{Deserialize, Serialize};

use crate::app::providers::config_getter::ConfigGetter;
use crate::app::providers::models::record::{PubNewRecord, PubRecord};

#[cfg(feature = "fetch")]
use crate::app::providers::services::fetch::Fetch;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubProject {
    pub id: i32,
    pub name: String,
    pub keys: Vec<Option<String>>,
}

#[cfg(feature = "fetch")]
impl PubProject {
    pub async fn init_user(
        fetch: &State<Fetch>,
        project_id: i32,
        user_id: i32,
    ) -> Result<Self, Status> {
        let robot_token = match Fetch::robot_token().await {
            Ok(token) => token,
            Err(_) => return Err(Status::InternalServerError),
        };

        let project_url = ConfigGetter::get_entity_url("project")
            .unwrap_or("http://localhost:8051/api/v1/project/".to_string())
            + project_id.to_string().as_str()
            + "/user/"
            + user_id.to_string().as_str()
            + "/new";

        let client = fetch.client.lock().await;
        let res = client
            .get(project_url)
            .header("Accept", "application/json")
            .header("Authorization", robot_token)
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

    pub async fn store_record(fetch: &State<Fetch>, project_id: i32, new_record: PubNewRecord) -> Result<PubRecord, Status> {
        let robot_token = match Fetch::robot_token().await {
            Ok(token) => token,
            Err(_) => return Err(Status::InternalServerError),
        };

        let project_url = ConfigGetter::get_entity_url("project")
            .unwrap_or("http://localhost:8051/api/v1/project/".to_string())
            + project_id.to_string().as_str()
            + "/record";

        let res;
        {
            let client = fetch.client.lock().await;
            res = client
                .post(project_url)
                .header("Accept", "application/json")
                .header("Authorization", robot_token)
                .header("Content-Type", "application/json")
                .json(&new_record)
                .send()
                .await;
        }

        match res {
            Ok(res) => {
                if !res.status().is_success() {
                    return Err(Status::from_code(res.status().as_u16()).unwrap());
                }

                Ok(res.json::<PubRecord>().await.unwrap())
            }
            Err(_) => Err(Status::InternalServerError),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubProjectWithRecords {
    pub id: i32,
    pub name: String,
    pub keys: Vec<Option<String>>,
    pub records: Option<Vec<PubRecord>>,
}
