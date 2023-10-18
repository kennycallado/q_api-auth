use chrono::{DateTime, NaiveDateTime, Utc};
use rocket::serde::uuid::Uuid;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubCronJob {
    pub id: i32,
    pub owner: String,
    pub service: String,
    pub route: String,
    pub job: PubEJob,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubEJob {
    pub id: Uuid,
    pub status: String,
    pub schedule: String,
    pub since: Option<NaiveDateTime>,
    pub until: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubNewCronJob {
    pub service: String,
    pub route: String,
    pub job: NewEJob,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct NewEJob {
    pub schedule: String,
    pub since: Option<NaiveDateTime>,
    pub until: Option<NaiveDateTime>,
}

impl From<PubCronJob> for PubNewCronJob {
    fn from(cronjob: PubCronJob) -> Self {
        PubNewCronJob {
            service: cronjob.service,
            route: cronjob.route,
            job: NewEJob {
                schedule: cronjob.job.schedule,
                since: cronjob.job.since,
                until: cronjob.job.until,
            },
        }
    }
}
