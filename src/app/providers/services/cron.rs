#![allow(unused)]

#[cfg(feature = "cron")]
use std::sync::Arc;

#[cfg(feature = "cron")]
use chrono::{DateTime, NaiveDateTime, Utc};

#[cfg(feature = "cron")]
use rocket::serde::{ uuid::Uuid, Serialize };
#[cfg(feature = "cron")]
use rocket::tokio::sync::Mutex;

#[cfg(feature = "cron")]
use tokio_cron_scheduler::{Job, JobScheduler, JobSchedulerError};

#[cfg(all(feature = "db", feature = "cron"))]
use diesel::{PgConnection, ConnectionError};
#[cfg(all(feature = "db", feature = "cron"))]
use diesel::prelude::*;
#[cfg(feature = "cron")]
use crate::database::schema::cronjobs;

#[cfg(feature = "cron")]
use crate::app::providers::models::cronjob::{PubCronJob, PubNewCronJob};

#[cfg(all(feature = "db", feature = "cron"))]
use crate::app::providers::config_getter::ConfigGetter;
#[cfg(all(feature = "db", feature = "cron"))]
use crate::app::providers::models::cronjob::DbCron;

#[cfg(feature = "cron")]
use super::claims::{Claims, UserInClaims};

#[cfg(feature = "cron")]
#[derive(Clone)]
pub struct CronManager {
    pub scheduler: Arc<Mutex<JobScheduler>>,
    pub jobs: Arc<Mutex<Vec<PubCronJob>>>,
    pub db_url: Option<String>,
}

#[cfg(feature = "cron")]
impl CronManager {
    pub async fn new(db_url: Option<String>) -> Self {
        let scheduler = JobScheduler::new().await.unwrap();
        let jobs = Arc::new(Mutex::new(Vec::new()));

        scheduler.start().await.unwrap();

        CronManager {
            scheduler: Arc::new(Mutex::new(scheduler)),
            jobs,
            db_url,
        }
    }

    #[cfg(feature = "db")]
    async fn db_connection(&self) -> Result<PgConnection, ConnectionError> {
        type Error = ConnectionError;

        match self.db_url {
            Some(ref url) => {
                PgConnection::establish(url)
            },
            None => Err(ConnectionError::BadConnection("No database url".to_string())),
        }
    }

    #[cfg(feature = "db")]
    pub async fn init_from_db(&self) {
        // create the connection
        let mut db = match self.db_connection().await {
            Ok(db) => DbCron(db),
            Err(_) => {
                println!("Error connecting to database");
                return ;
            },
        };

        // get all jobs from db
        let jobs = cronjobs::table.load::<PubCronJob>(&mut db.0);
        match jobs {
            Ok(jobs) => {
                for new_cronjob in jobs {
                     
                    if new_cronjob.status == "finished" { continue ; }

                    match self.wrap_create_job(new_cronjob.id, &new_cronjob.into()).await {
                        Ok(_) => (),
                        Err(e) => {
                            println!("Error creating job: {}", e);
                            return ;
                        },
                    }
                }
            },
            Err(e) => {
                println!("Error getting jobs from database: {}", e);
                return ;
            },
        }
    }

    #[cfg(feature = "db")]
    async fn wrap_create_job(&self, id: Uuid, new_cronjob: &PubNewCronJob) -> Result<Uuid, JobSchedulerError> {
        match self.create_job(new_cronjob).await {
            Ok(uuid) => {
                // remove old job
                self.remove_job(id).await.unwrap();

                Ok(uuid)
            },
            Err(e) => {
                println!("Error creating job: {}", e);
                Err(e)
            },
        }
    }

    pub async fn create_job(&self, new_cronjob: &PubNewCronJob) -> Result<Uuid, JobSchedulerError> {
        let service = ConfigGetter::get_entity_url(new_cronjob.service.as_str()).unwrap();
        let route = new_cronjob.route.clone();
        let manager = self.clone();

        let job = Job::new_async(new_cronjob.schedule.as_str(), move |uuid, mut lock|  {
            let url = format!("{}{}", service, route);
            let manager = manager.clone();

            Box::pin(async move {
                let job = manager.get_job(uuid).await.unwrap();
                let next_tick = lock.next_tick_for_job(uuid).await.unwrap().unwrap().naive_utc();
                let until = job.until.clone();

                manager.status_hanler(&mut lock, job, next_tick).await;

                if let Some(until) = until {
                    if until < next_tick {
                        // change state to finished
                        manager.update_status(uuid, "finished").await.unwrap();
                        // lock.remove(&uuid).await.unwrap();

                        return ;
                    }
                }

                let robo_token = Claims::from(UserInClaims::default()).enconde_for_robot();
                let res;
                {
                    let client = reqwest::Client::new();
                    res = client
                        .get(url)
                        .bearer_auth(robo_token.unwrap())
                        .header("Accept", "application/json")
                        .send().await;
                }

                if let Err(e) = res {
                    println!("Error: {};", e);

                    // change the state to error
                    manager.update_status(uuid, "error").await.unwrap();
                    // lock.remove(&uuid).await.unwrap();
               }
            })
        });

        match job {
            Ok(job) => {
                let id = job.guid();

                self.add_job(job, new_cronjob).await.unwrap();

                Ok(id)
            },
            Err(e) => {
                println!("Error: {};", e);
                return Err(e);
            },
        }
    }

    pub async fn get_jobs(&self) -> Vec<PubCronJob> {
        let jobs = self.jobs.lock().await;

        jobs.clone()
    }

    pub async fn get_job(&self, id: Uuid) -> Option<PubCronJob> {
        let jobs = self.jobs.lock().await;

        jobs.iter().find(|job| job.id == id).cloned()
    }

    pub async fn add_job(&self, job: Job, cron_job: &PubNewCronJob) -> Result<(), JobSchedulerError> {
        let scheduler = self.scheduler.lock().await;
        let mut jobs = self.jobs.lock().await;

        let uuid = scheduler.add(job).await?;
        let now = DateTime::<Utc>::from(std::time::SystemTime::now());

        let status;
        match cron_job.since {
            Some(since) => {
                if now < since { status = "pending".to_owned(); }
                else { status = "active".to_owned(); }
            },
            None => {
                status = "active".to_owned();
            }
        }

        let since: Option<NaiveDateTime> = match cron_job.since {
            Some(mut since) => {
                Some(since.with_timezone(&Utc).naive_utc())
            },
            None => None
        };

        let until: Option<NaiveDateTime> = match cron_job.until {
            Some(mut until) => {
                Some(until.with_timezone(&Utc).naive_utc())
            },
            None => None
        };

        let job = PubCronJob {
            id: uuid,
            schedule: cron_job.schedule.clone(),
            service: cron_job.service.clone(),
            status,
            route: cron_job.route.clone(),
            since,
            until,
        };

        #[cfg(feature = "db")]
        {
            let mut db = self.db_connection().await.unwrap();
            diesel::insert_into(cronjobs::table)
                .values(job.clone())
                .execute(&mut db).expect("Error saving new cronjob");
        }

        jobs.push(job);

        Ok(())
    }

    #[cfg(feature = "db")]
    async fn remove_db(&self, id: Uuid) {
        let mut db = self.db_connection().await.unwrap();

        diesel::delete(cronjobs::table.find(id))
            .execute(&mut db).expect("Error there is no cronjob with this id in db");
    }


    pub async fn remove_job(&self, id: Uuid) -> Result<(), JobSchedulerError> {
        let scheduler = self.scheduler.lock().await;
        let mut jobs = self.jobs.lock().await;

        // let job = jobs.iter().find(|job| job.id == id).unwrap();
        match jobs.iter().find(|job| job.id == id) {
            Some(job) => {
                scheduler.remove(&job.id).await?;

                jobs.retain(|job| job.id != id);

                #[cfg(feature = "db")]
                self.remove_db(id).await;

                Ok(())
            },
            None => {
                // This means that the job is not in memory,
                // so we need to remove from the database
                #[cfg(feature = "db")]
                self.remove_db(id).await;

                return Ok(());
            }
        }
    }

    async fn update_db(&self, id: Uuid, new_cronjob: &PubNewCronJob) {
        let mut db = self.db_connection().await.unwrap();

        diesel::update(cronjobs::table.find(id))
            .set(new_cronjob)
            .execute(&mut db).expect("Error updating cronjob in db");
    }

    pub async fn update_status(&self, id: Uuid, status: &str) -> Result<(), JobSchedulerError> {
        let mut jobs = self.jobs.lock().await;

        let job = jobs.iter_mut().find(|job| job.id == id).unwrap();
        job.status = status.to_owned();

        #[cfg(feature = "db")]
        {
            let new_cronjob = job.clone().into();
            self.update_db(id, &new_cronjob).await;
        }

        Ok(())
    }

    pub async fn update_since(&self, id: Uuid, since: Option<NaiveDateTime>) -> Result<(), JobSchedulerError> {
        let mut jobs = self.jobs.lock().await;

        let job = jobs.iter_mut().find(|job| job.id == id).unwrap();
        job.since = since;

        #[cfg(feature = "db")]
        {
            let new_cronjob = job.clone().into();
            self.update_db(id, &new_cronjob).await;
        }

        Ok(())
    }


    pub async fn update_until(&self, id: Uuid, until: Option<NaiveDateTime>) -> Result<(), JobSchedulerError> {
        let mut jobs = self.jobs.lock().await;

        let job = jobs.iter_mut().find(|job| job.id == id).unwrap();
        job.until = until;

        #[cfg(feature = "db")]
        {
            let new_cronjob = job.clone().into();
            self.update_db(id, &new_cronjob).await;
        }

        Ok(())
    }

    pub async fn status_hanler(&self, mut lock: &mut JobScheduler, job: PubCronJob, next_tick: NaiveDateTime) {
        match job.status.as_str() {
            "finished" => {
                println!("Job {} finished", job.id);
                println!("Removing job from scheduler");

                lock.remove(&job.id).await.unwrap();
                return ;
            },
            "error" => {
                println!("Job {} failed", job.id);
                println!("Removing job from scheduler");

                lock.remove(&job.id).await.unwrap();
                return ;
            },
            "pending" => {
                if let Some(since) = job.since {
                    if since < next_tick {
                        // change state to active
                        &self.update_status(job.id, "active").await.unwrap();
                    } else {
                        return ;
                    }
                } else {
                    // change state to active
                    &self.update_status(job.id, "active").await.unwrap();
                }
            },
            _ => {}
        }
    }
}
