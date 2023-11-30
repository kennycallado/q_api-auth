use rocket_db_pools::{sqlx, Database};

use escalon_jobs::manager::{ContextTrait, EscalonJobsManager, EscalonJobsManagerTrait};
use escalon_jobs::{EscalonJob, EscalonJobStatus, EscalonJobTrait, NewEscalonJob};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{async_trait, Build, Rocket};
use sqlx::types::Uuid;
use std::borrow::BorrowMut;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::app::modules::cron::model::{CronJob, CronJobComplete, NewCronJob};
use crate::app::modules::escalon::model::{EJob, NewEJob};
use crate::app::providers::config_getter::ConfigGetter;
use crate::database::connection::Db;

#[derive(Clone)]
pub struct Context {
    pub db: sqlx::PgPool,
    pub fetch: reqwest::Client,
}

#[async_trait]
impl ContextTrait<Context> for Context {
    async fn update_job(&self, context: &Context, job: EscalonJob) {
        let job: EJob = job.into();

        sqlx::query!(
            r#"
            UPDATE escalonjobs SET status = $1 WHERE id = $2
            "#,
            job.status,
            job.id,
        )
        .execute(&context.db)
        .await
        .unwrap();
    }
}

pub struct CronManager(pub EscalonJobsManager<Context>);

impl CronManager {
    pub async fn init(rocket: Rocket<Build>) -> Rocket<Build> {
        let db = Db::fetch(&rocket).unwrap().0.clone();

        let fetch = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let manager = EscalonJobsManager::new(Context { db, fetch });
        let mut manager = manager
            .set_id(ConfigGetter::get_identity())
            .set_addr("0.0.0.0".parse::<IpAddr>().unwrap())
            .set_port(ConfigGetter::get_udp_port().unwrap_or(65056))
            .set_functions(Functions)
            .build()
            .await;

        manager.init().await;

        let cron_manager = CronManager(manager);
        cron_manager.take_jobs_on_init().await;

        rocket.manage(cron_manager)
    }

    pub fn inner(&self) -> &EscalonJobsManager<Context> {
        &self.0
    }
}

impl CronManager {
    pub async fn take_jobs_on_init(&self) {
        let own_jobs = sqlx::query!(
            r#"
            SELECT cronjobs.id AS cron_id, escalonjobs.*
            FROM cronjobs
            INNER JOIN escalonjobs ON escalonjobs.id = cronjobs.job_id
            WHERE cronjobs.owner = $1
            AND escalonjobs.status != 'done'
            AND escalonjobs.status != 'failed'
            "#,
            ConfigGetter::get_identity()
        )
        .fetch_all(&self.inner().context.db)
        .await
        .unwrap();

        let own_jobs: Vec<(i32, EJob)> = own_jobs
            .into_iter()
            .map(|job| {
                let id = job.cron_id;
                let job = EJob {
                    id: job.id,
                    status: job.status,
                    schedule: job.schedule,
                    since: job.since.map(|d| d.into()),
                    until: job.until.map(|d| d.into()),
                };
                (id, job)
            })
            .collect();

        for job in own_jobs {
            let old_uuid = job.1.id;
            let new_ejob: NewEJob = job.1.into();
            let escalon_job = self.inner().add_job(new_ejob).await;
            let ejob: EJob = escalon_job.clone().into();

            sqlx::query!(
                r#"
                INSERT INTO escalonjobs VALUES ($1, $2, $3, $4, $5)
                "#,
                ejob.id,
                ejob.status,
                ejob.schedule,
                ejob.since,
                ejob.until,
            )
            .execute(&self.inner().context.db)
            .await
            .unwrap();

            sqlx::query!(
                r#"
                UPDATE cronjobs SET owner = $1, job_id = $2 WHERE id = $3
                "#,
                ConfigGetter::get_identity(),
                escalon_job.job_id,
                job.0,
            )
            .execute(&self.inner().context.db)
            .await
            .unwrap();

            sqlx::query!(
                r#"
                DELETE FROM escalonjobs WHERE id = $1
                "#,
                old_uuid,
            )
            .execute(&self.inner().context.db)
            .await
            .unwrap();
        }

        let other_jobs = sqlx::query!(
            r#"
            SELECT cronjobs.id AS cron_id, escalonjobs.*
            FROM cronjobs
            INNER JOIN escalonjobs ON escalonjobs.id = cronjobs.job_id
            WHERE cronjobs.owner != $1
            AND escalonjobs.status != 'done'
            AND escalonjobs.status != 'failed'
            "#,
            ConfigGetter::get_identity()
        )
        .fetch_all(&self.inner().context.db)
        .await
        .unwrap();

        let other_jobs: Vec<(i32, EJob)> = other_jobs
            .into_iter()
            .map(|job| {
                let id = job.cron_id;
                let job = EJob {
                    id: job.id,
                    status: job.status,
                    schedule: job.schedule,
                    since: job.since.map(|d| d.into()),
                    until: job.until.map(|d| d.into()),
                };
                (id, job)
            })
            .collect();

        if !other_jobs.is_empty() {
            let jobs = other_jobs.clone();
            let manager = self.inner().clone();

            rocket::tokio::spawn(async move {
                rocket::tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                let clients = manager.clients.clone().unwrap();
                let own_start_time = manager.start_time.clone().unwrap();

                if clients
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|client| {
                        let client_time = client.1.start_time;
                        match client_time.duration_since(own_start_time) {
                            Ok(_) => true,
                            Err(_) => false,
                        }
                    })
                    .is_some()
                {
                    return;
                }

                for job in jobs {
                    if !clients.lock().unwrap().contains_key(&job.1.id.to_string()) {
                        let old_uuid = job.1.id;
                        let new_ejob: NewEJob = job.1.into();
                        let escalon_job = manager.add_job(new_ejob).await;
                        let ejob: EJob = escalon_job.clone().into();

                        sqlx::query!(
                            r#"
                            INSERT INTO escalonjobs VALUES ($1, $2, $3, $4, $5)
                            "#,
                            ejob.id,
                            ejob.status,
                            ejob.schedule,
                            ejob.since,
                            ejob.until,
                        )
                        .execute(&manager.context.db)
                        .await
                        .unwrap();

                        sqlx::query!(
                            r#"
                            UPDATE cronjobs SET owner = $1, job_id = $2 WHERE id = $3
                            "#,
                            ConfigGetter::get_identity(),
                            escalon_job.job_id,
                            job.0,
                        )
                        .execute(&manager.context.db)
                        .await
                        .unwrap();

                        sqlx::query!(
                            r#"
                            DELETE FROM escalonjobs WHERE id = $1
                            "#,
                            old_uuid,
                        )
                        .execute(&manager.context.db)
                        .await
                        .unwrap();
                    }
                }

                return;
            });
        }
    }
}

struct Functions;

#[async_trait]
impl EscalonJobsManagerTrait<Context> for Functions {
    async fn take_jobs(
        &self,
        manager: &EscalonJobsManager<Context>,
        from_client: String,
        start_at: usize,
        n_jobs: usize,
    ) -> Result<Vec<String>, ()> {
        let jobs = sqlx::query!(
            r#"
            SELECT cronjobs.id AS cron_id, escalonjobs.*
            FROM cronjobs
            INNER JOIN escalonjobs ON escalonjobs.id = cronjobs.job_id
            WHERE cronjobs.owner = $1
            LIMIT $2
            OFFSET $3
            "#,
            from_client,
            n_jobs as i64,
            start_at as i64,
        )
        .fetch_all(&manager.context.db)
        .await
        .unwrap();

        let jobs: Vec<(i32, EJob)> = jobs
            .into_iter()
            .map(|job| {
                let id = job.cron_id;
                let job = EJob {
                    id: job.id,
                    status: job.status,
                    schedule: job.schedule,
                    since: job.since.map(|d| d.into()),
                    until: job.until.map(|d| d.into()),
                };
                (id, job)
            })
            .collect();

        let mut response = Vec::new();
        for job in jobs {
            let id = job.0;
            let job = job.1;
            let old_uuid = job.id;

            let new_ejob: NewEJob = job.into();
            let escalon_job = manager.add_job(new_ejob).await;
            let ejob: EJob = escalon_job.clone().into();

            sqlx::query!(
                r#"
                INSERT INTO escalonjobs VALUES ($1, $2, $3, $4, $5)
                "#,
                ejob.id,
                ejob.status,
                ejob.schedule,
                ejob.since,
                ejob.until,
            )
            .execute(&manager.context.db)
            .await
            .unwrap();

            sqlx::query!(
                r#"
                UPDATE cronjobs SET owner = $1, job_id = $2 WHERE id = $3
                "#,
                ConfigGetter::get_identity(),
                escalon_job.job_id,
                id,
            )
            .execute(&manager.context.db)
            .await
            .unwrap();

            response.push(old_uuid.to_string());
        }

        Ok(response)
    }

    async fn drop_jobs(
        &self,
        manager: &EscalonJobsManager<Context>,
        jobs: Vec<String>,
    ) -> Result<(), ()> {
        let mut _affected_rows: usize = 0;

        for ejob_id in jobs {
            let ejob_id = Uuid::parse_str(ejob_id.as_str()).unwrap();

            let rows = sqlx::query!(
                r#"
                DELETE FROM escalonjobs WHERE id = $1
                "#,
                ejob_id,
            )
            .execute(&manager.context.db)
            .await
            .unwrap();

            _affected_rows += rows.rows_affected() as usize;

            if (manager.get_job(ejob_id).await).is_some() {
                manager.remove_job(ejob_id).await;
            }
        }

        Ok(())
    }
}
