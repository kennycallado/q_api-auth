use serde::{Deserialize, Serialize};

use crate::app::providers::models::question::PubQuestion;
use crate::app::providers::models::slide::PubSlide;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubResourceContent {
    pub slides: Option<Vec<PubSlide>>,
    pub form: Option<Vec<PubQuestion>>,
    pub external: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubResource {
    pub id: i32,
    pub resource_type: String,
    pub title: String,
    pub description: String,
    pub content: Option<PubResourceContent>,
}
