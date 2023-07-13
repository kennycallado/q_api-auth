use serde::{Deserialize, Serialize};

use crate::app::providers::models::answer::PubNewAnswer;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubPaperPush {
    pub id: i32,
    pub user_id: i32,
    pub user_record: rocket::serde::json::Value,
    pub project_id: i32,
    pub resource_id: i32,
    pub completed: bool,
    pub answers: Option<Vec<PubNewAnswer>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubPaper {
    pub id: i32,
    pub project_id: i32,
    pub resource_id: i32,
    pub completed: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubNewPaper {
    pub user_id: i32,
    pub project_id: i32,
    pub resource_id: i32,
    pub completed: bool,
}
