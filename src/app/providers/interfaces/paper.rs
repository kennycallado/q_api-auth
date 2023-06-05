use serde::{Deserialize, Serialize};

use crate::app::providers::interfaces::answer::PubNewAnswer;

#[derive(Debug, Clone, Deserialize, Serialize)]
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
