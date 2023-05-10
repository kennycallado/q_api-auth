use std::fmt;

use serde::{Deserialize, Serialize};

use crate::app::providers::interfaces::question::PubQuestion;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubSlide {
    pub id: i32,
    pub slide_type: SlideType,
    pub title: String,
    pub content: Option<String>,
    pub question: Option<PubQuestion>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubNewSlide {
    pub slide_type: SlideType,
    pub title: String,
    pub content: Option<String>,
    pub question: Option<PubQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SlideType {
    Content,
    Input,
}

impl fmt::Display for SlideType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match *self {
                SlideType::Content => "content",
                SlideType::Input => "input",
            }
        )
    }
}
