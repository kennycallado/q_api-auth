#![allow(unused)]

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ConfigGetter {
    pub origin_url: Option<String>,
    pub secret_key: Option<String>,
    //
    pub profile_url: Option<String>,
    pub user_url: Option<String>,
    pub auth_url: Option<String>,
    //
    pub fcm_url: Option<String>,
    //
    pub question_url: Option<String>,
    pub answer_url: Option<String>,
    //
    pub slide_url: Option<String>,
    pub form_url: Option<String>,
    pub external_url: Option<String>,
    //
    pub resource_url: Option<String>,
    pub paper_url: Option<String>,
    //
    pub logic_url: Option<String>,
    pub checker_url: Option<String>,
    //
    pub project_url: Option<String>,
    pub cron_url: Option<String>,
}

impl ConfigGetter {
    pub fn get_entity_url(entity: &str) -> Option<String> {
        match entity {
            "profile" => ConfigGetter::get_profile_url(),
            "user" => ConfigGetter::get_user_url(),
            "auth" => ConfigGetter::get_auth_url(),
            //
            "fcm" => ConfigGetter::get_fcm_url(),
            //
            "question" => ConfigGetter::get_question_url(),
            "answer" => ConfigGetter::get_answer_url(),
            //
            "slide" => ConfigGetter::get_slide_url(),
            "form" => ConfigGetter::get_form_url(),
            "external" => ConfigGetter::get_external_url(),
            //
            "resource" => ConfigGetter::get_resource_url(),
            "paper" => ConfigGetter::get_paper_url(),
            //
            "logic" => ConfigGetter::get_logic_url(),
            "checker" => ConfigGetter::get_checker_url(),
            //
            "project" => ConfigGetter::get_project_url(),
            "cron" => ConfigGetter::get_project_url(),
            _ => None,
        }
    }

    pub fn get_origin_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .origin_url
    }

    pub fn get_secret_key() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .secret_key
    }
}

impl ConfigGetter {
    fn get_profile_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .profile_url
    }

    fn get_user_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .user_url
    }

    fn get_auth_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .auth_url
    }

    fn get_fcm_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .fcm_url
    }

    fn get_question_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .question_url
    }

    fn get_answer_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .answer_url
    }

    fn get_slide_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .slide_url
    }

    fn get_form_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .form_url
    }

    fn get_external_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .external_url
    }

    fn get_resource_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .resource_url
    }

    fn get_paper_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .paper_url
    }

    fn get_logic_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .logic_url
    }

    fn get_checker_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .checker_url
    }

    fn get_project_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .project_url
    }

    fn get_cron_url() -> Option<String> {
        rocket::Config::figment()
            .extract::<ConfigGetter>()
            .unwrap()
            .cron_url
    }
}
