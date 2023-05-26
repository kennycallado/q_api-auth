#[cfg(feature = "cron")]
use std::sync::Arc;

#[cfg(feature = "cron")]
use rocket::serde::uuid::Uuid;
#[cfg(feature = "cron")]
use rocket::tokio::sync::Mutex;

#[cfg(feature = "cron")]
use tokio_cron_scheduler::{Job, JobScheduler, JobSchedulerError};

#[cfg(feature = "cron")]
#[derive(Clone)]
pub struct JobManager {
    pub id: i32,
    pub job: Uuid,
}

#[cfg(feature = "cron")]
pub struct CronManager {
    pub scheduler: Arc<Mutex<JobScheduler>>,
    pub jobs: Arc<Mutex<Vec<JobManager>>>,
}

#[cfg(feature = "cron")]
impl CronManager {
    pub async fn new() -> Self {
        let scheduler = JobScheduler::new().await.unwrap();
        let jobs = Arc::new(Mutex::new(Vec::new()));

        scheduler.start().await.unwrap();

        CronManager {
            scheduler: Arc::new(Mutex::new(scheduler)),
            jobs,
        }
    }

    pub async fn get_jobs(&self) -> Vec<JobManager> {
        let jobs = self.jobs.lock().await;

        jobs.clone()
    }

    pub async fn add_job(&self, job: Job) -> Result<(), JobSchedulerError> {
        let scheduler = self.scheduler.lock().await;
        let mut jobs = self.jobs.lock().await;

        let uuid = scheduler.add(job).await?;
        let job = JobManager {
            id: jobs.len() as i32,
            job: uuid,
        };

        jobs.push(job);

        Ok(())
    }

    pub async fn remove_job(&self, id: i32) -> Result<(), JobSchedulerError> {
        let scheduler = self.scheduler.lock().await;
        let mut jobs = self.jobs.lock().await;

        let job = jobs.iter().find(|job| job.id == id).unwrap();
        scheduler.remove(&job.job).await?;

        jobs.retain(|job| job.id != id);

        Ok(())
    }
}
