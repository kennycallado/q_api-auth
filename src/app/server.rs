#[cfg(feature = "db")]
use rocket::fairing::AdHoc;

use crate::config::cors;
#[cfg(feature = "db")]
use crate::config::database;

#[cfg(feature = "cron")]
use super::providers::interfaces::helpers::cron::CronManager;
#[cfg(feature = "fetch")]
use super::providers::interfaces::helpers::fetch::Fetch;

use super::modules::routing as modules_routing;
use super::routing as service_routing;

#[launch]
pub async fn rocket() -> _ {
    #[allow(unused_mut)]
    let mut rocket_build = rocket::build();

    // Only attach the database if feature is enabled
    #[cfg(feature = "db")]
    {
        rocket_build = rocket_build
            .attach(database::Db::fairing())
            .attach(AdHoc::on_ignite(
                "Diesel Migrations",
                database::run_migrations,
            ));
    }

    // Only manage the fetch if feature is enabled
    #[cfg(feature = "fetch")]
    {
        rocket_build = rocket_build.manage(Fetch::new());
    }

    // Only manage the cron if cron is true
    #[cfg(feature = "cron")]
    {
        rocket_build = rocket_build.manage(CronManager::new().await);
    }

    rocket_build
        .attach(cors::Cors)
        .attach(service_routing::router())
        .attach(modules_routing::router())
}
