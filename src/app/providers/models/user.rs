use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Role {
    pub id: i32,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubUser {
    pub id: i32,
    pub depends_on: i32,
    pub role_id: i32,
    pub user_token: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}


#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct UserProject {
    pub id: i32,
    pub user_id: i32,
    pub project_id: i32,
    pub active: bool,
    pub keys: Vec<Option<String>>,
    pub record: Option<rocket::serde::json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubUserExpanded {
    pub id: i32,
    pub depends_on: PubUser,
    pub role: Role,
    pub user_token: Option<String>,
    pub project: UserProject,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubNewUser {
    pub depends_on: i32,
    pub role_id: i32,
    pub active: Option<bool>,
    pub project_id: i32,
}
