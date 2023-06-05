use serde::{Deserialize, Serialize};

use crate::app::providers::interfaces::question::PubQuestion;
use crate::app::providers::interfaces::slide::PubSlide;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubResourceContent {
    pub slides: Option<Vec<PubSlide>>,
    pub form: Option<Vec<PubQuestion>>,
    pub external: Option<i32>,
}
 
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubResource {
    pub id: i32,
    pub title: String,
    pub description: String,
    pub content: Option<PubResourceContent>,
}
