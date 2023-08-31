use chrono::{DateTime, Utc, NaiveDateTime};
use rocket::serde::uuid::Uuid;
use serde::{Deserialize, Serialize};
#[cfg(feature = "db")]
#[cfg(feature = "cron")]
use diesel::PgConnection;

#[cfg(feature = "cron")]
use crate::database::schema::cronjobs;

#[cfg(feature = "cron")]
#[cfg(feature = "db")]
#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(treat_none_as_null = true)]
#[diesel(table_name = cronjobs)]
#[serde(crate = "rocket::serde")]
pub struct PubCronJob {
    pub id: Uuid,
    pub schedule: String,
    pub service: String,
    pub status: String,
    pub route: String,
    pub since: Option<NaiveDateTime>,
    pub until: Option<NaiveDateTime>,
}

#[cfg(not(feature = "db"))]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubCronJob {
    pub id: Uuid,
    pub schedule: String,
    pub service: String,
    pub status: String,
    pub route: String,
    pub since: Option<NaiveDateTime>,
    pub until: Option<NaiveDateTime>,
}

#[cfg(feature = "db")]
#[cfg(feature = "cron")]
#[derive(Debug, Deserialize, Serialize, AsChangeset)]
#[diesel(treat_none_as_null = true)]
#[diesel(table_name = cronjobs)]
#[serde(crate = "rocket::serde")]
pub struct PubNewCronJob {
    pub schedule: String,
    pub service: String,
    pub status: String,
    pub route: String,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>
}

#[cfg(not(feature = "db"))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PubNewCronJob {
    pub schedule: String,
    pub service: String,
    pub status: String,
    pub route: String,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>
}

#[cfg(feature = "cron")]
impl From<PubCronJob> for PubNewCronJob {
    fn from(cronjob: PubCronJob) -> Self {
        PubNewCronJob {
            schedule: cronjob.schedule,
            service: cronjob.service,
            status: cronjob.status,
            route: cronjob.route,
            since: cronjob.since.map(|d| DateTime::from_utc(d, Utc)),
            until: cronjob.until.map(|d| DateTime::from_utc(d, Utc)),
        }
    }
}

#[cfg(feature = "db")]
#[cfg(feature = "cron")]
pub struct DbCron(pub PgConnection);
