#![allow(unused)]
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubRecord {
    pub id: i32,
    pub user_id: i32,
    pub record: rocket::serde::json::Value,
}

#[derive(Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubNewRecord {
    pub user_id: i32,
    pub record: Option<rocket::serde::json::Value>,
}
