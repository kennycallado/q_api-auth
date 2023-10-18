use diesel::PgConnection;
use escalon_jobs::manager::{ContextTrait, EscalonJobsManager, EscalonJobsManagerTrait};
use escalon_jobs::{EscalonJob, EscalonJobStatus, EscalonJobTrait, NewEscalonJob};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{async_trait, Build, Rocket};
use rocket_sync_db_pools::ConnectionPool;
use std::net::IpAddr;
use std::time::Duration;

use crate::app::modules::cron::model::{CronJob, CronJobComplete, NewCronJob};
use crate::app::providers::config_getter::ConfigGetter;
use crate::database::connection::Db;

pub type ContextDb = ConnectionPool<Db, PgConnection>;

#[derive(Clone)]
pub struct Context<T> {
    pub db_pool: T,
    pub fetch: reqwest::Client,
}

#[async_trait]
impl ContextTrait<Context<ContextDb>> for Context<ContextDb> {
    async fn update_job(&self, context: &Context<ContextDb>, job: EscalonJob) {
        use diesel::prelude::*;

        use crate::app::modules::escalon::model::{EJob, NewEJob};
        use crate::database::schema::{cronjobs, escalonjobs};

        let job: EJob = job.into();

        context
            .db_pool
            .get()
            .await
            .unwrap()
            .run(move |conn| {
                diesel::update(escalonjobs::table)
                    .filter(escalonjobs::id.eq(&job.id))
                    .set(&job)
                    .execute(conn)
                    .unwrap();
            })
            .await;
    }
}

pub struct CronManager(pub EscalonJobsManager<Context<ContextDb>>);

impl CronManager {
    pub async fn init(rocket: Rocket<Build>) -> Rocket<Build> {
        let pool = match Db::pool(&rocket) {
            Some(pool) => pool.clone(),
            None => return rocket,
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let manager = EscalonJobsManager::new(Context {
            db_pool: pool,
            fetch: client,
        });

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

    pub fn inner(&self) -> &EscalonJobsManager<Context<ContextDb>> {
        &self.0
    }
}

impl CronManager {
    pub async fn take_jobs_on_init(&self) {
        use diesel::prelude::*;

        use crate::app::modules::cron::model::{CronJob, NewCronJob};
        use crate::app::modules::escalon::model::{EJob, NewEJob};
        use crate::database::schema::{cronjobs, escalonjobs};

        let jobs = self
            .inner()
            .context
            .db_pool
            .get()
            .await
            .unwrap()
            .run(move |conn| {
                let own_jobs: Vec<(i32, EJob)> = cronjobs::table
                    .inner_join(escalonjobs::table)
                    .filter(cronjobs::owner.eq(ConfigGetter::get_identity()))
                    .filter(escalonjobs::status.ne("done"))
                    .filter(escalonjobs::status.ne("failed"))
                    .select((cronjobs::id, escalonjobs::all_columns))
                    .load::<(i32, EJob)>(conn)
                    .unwrap();

                let other_jobs: Vec<((i32, String), EJob)> = cronjobs::table
                    .inner_join(escalonjobs::table)
                    .filter(cronjobs::owner.ne(ConfigGetter::get_identity()))
                    .select(((cronjobs::id, cronjobs::owner), escalonjobs::all_columns))
                    .load::<((i32, String), EJob)>(conn)
                    .unwrap();

                (own_jobs, other_jobs)
            })
            .await;

        // Agrego los jobs propios
        for job in jobs.0 {
            let old_uuid = job.1.id;
            let new_ejob: NewEJob = job.1.into();
            let escalon_job = self.inner().add_job(new_ejob).await;
            let ejob: EJob = escalon_job.clone().into();

            self.inner()
                .context
                .db_pool
                .get()
                .await
                .unwrap()
                .run(move |conn| {
                    diesel::insert_into(escalonjobs::table)
                        .values(ejob)
                        .execute(conn)
                        .unwrap();

                    diesel::update(cronjobs::table)
                        .filter(cronjobs::id.eq(job.0))
                        .set((
                            cronjobs::owner.eq(ConfigGetter::get_identity()),
                            cronjobs::job_id.eq(&escalon_job.job_id),
                        ))
                        .execute(conn)
                        .unwrap();

                    diesel::delete(escalonjobs::table)
                        .filter(escalonjobs::id.eq(old_uuid))
                        .execute(conn)
                        .unwrap();
                })
                .await;
        }

        if !jobs.1.is_empty() {
            let jobs = jobs.1.clone();
            let manager = self.inner().clone();

            rocket::tokio::spawn(async move {
                rocket::tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                for job in jobs {
                    let clients = manager.clients.clone().unwrap();

                    if !clients.lock().unwrap().contains_key(&job.0 .1) {
                        let old_uuid = job.1.id;
                        let new_ejob: NewEJob = job.1.into();
                        let escalon_job = manager.add_job(new_ejob).await;
                        let ejob: EJob = escalon_job.clone().into();

                        manager
                            .context
                            .db_pool
                            .get()
                            .await
                            .unwrap()
                            .run(move |conn| {
                                diesel::insert_into(escalonjobs::table)
                                    .values(ejob)
                                    .execute(conn)
                                    .unwrap();

                                diesel::update(cronjobs::table)
                                    .filter(cronjobs::id.eq(job.0 .0))
                                    .set((
                                        cronjobs::owner.eq(ConfigGetter::get_identity()),
                                        cronjobs::job_id.eq(&escalon_job.job_id),
                                    ))
                                    .execute(conn)
                                    .unwrap();

                                diesel::delete(escalonjobs::table)
                                    .filter(escalonjobs::id.eq(old_uuid))
                                    .execute(conn)
                                    .unwrap();
                            })
                            .await;
                    }
                }
            });
        }
    }
}

struct Functions;

#[async_trait]
impl EscalonJobsManagerTrait<Context<ContextDb>> for Functions {
    async fn take_jobs(
        &self,
        manager: &EscalonJobsManager<Context<ContextDb>>,
        from_client: String,
        start_at: usize,
        n_jobs: usize,
    ) -> Result<Vec<String>, ()> {
        use diesel::prelude::*;

        use crate::app::modules::escalon::model::{EJob, NewEJob};
        use crate::database::schema::{cronjobs, escalonjobs};

        let jobs: Vec<(i32, EJob)> = manager
            .context
            .db_pool
            .get()
            .await
            .unwrap()
            .run(move |conn| {
                cronjobs::table
                    .filter(cronjobs::owner.eq(&from_client))
                    .limit(n_jobs as i64)
                    .offset(start_at as i64)
                    .inner_join(escalonjobs::table)
                    .select((cronjobs::id, escalonjobs::all_columns))
                    .load::<(i32, EJob)>(conn)
                    .unwrap()
            })
            .await;

        let mut response = Vec::new();
        for job in jobs {
            let id = job.0;
            let job = job.1;
            let old_uuid = job.id;

            let new_ejob: NewEJob = job.into();
            let escalon_job = manager.add_job(new_ejob).await;
            let ejob: EJob = escalon_job.clone().into();

            manager
                .context
                .db_pool
                .get()
                .await
                .unwrap()
                .run(move |conn| {
                    diesel::insert_into(escalonjobs::table)
                        .values(ejob)
                        .execute(conn)
                        .unwrap();

                    diesel::update(cronjobs::table)
                        .filter(cronjobs::id.eq(id))
                        .set((
                            cronjobs::owner.eq(ConfigGetter::get_identity()),
                            cronjobs::job_id.eq(&escalon_job.job_id),
                        ))
                        .execute(conn)
                        .unwrap();
                })
                .await;

            response.push(old_uuid.to_string());
        }

        Ok(response)
    }

    async fn drop_jobs(
        &self,
        manager: &EscalonJobsManager<Context<ContextDb>>,
        jobs: Vec<String>,
    ) -> Result<(), ()> {
        use diesel::prelude::*;
        use rocket::serde::uuid::Uuid;

        use crate::database::schema::{cronjobs, escalonjobs};

        // let mut affected_rows: usize = 0;
        for ejob_id in jobs {
            let ejob_id = Uuid::parse_str(ejob_id.as_str()).unwrap();

            // let rows = manager
            manager
                .context
                .db_pool
                .get()
                .await
                .unwrap()
                .run(move |conn| {
                    diesel::delete(escalonjobs::table)
                        .filter(escalonjobs::id.eq(&ejob_id))
                        .execute(conn)
                        .unwrap()
                })
                .await;

            // affected_rows += rows;

            if (manager.get_job(ejob_id).await).is_some() {
                manager.remove_job(ejob_id).await;
            }
        }

        Ok(())
    }
}
