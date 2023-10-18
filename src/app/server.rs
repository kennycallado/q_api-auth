#[cfg(feature = "cron")]
use crate::app::providers::services::cron::CronManager;

#[cfg(feature = "db")]
use crate::database::connection;
#[cfg(feature = "db")]
use rocket::fairing::AdHoc;

#[cfg(feature = "fetch")]
use crate::app::providers::services::fetch::Fetch;

use crate::app::providers::cors;

use super::modules::routing as modules_routing;
use super::routing as service_routing;

#[launch]
pub async fn rocket() -> _ {
    #[allow(unused_mut)]
    let mut rocket_build = rocket::build();

    #[cfg(feature = "db")]
    {
        rocket_build = rocket_build
            .attach(connection::Db::fairing())
            .attach(AdHoc::on_ignite(
                "Diesel Migrations",
                connection::run_migrations,
            ));
    }

    #[cfg(feature = "fetch")]
    {
        rocket_build = rocket_build.manage(Fetch::new());
    }

    #[cfg(feature = "cron")]
    {
        rocket_build =
            rocket_build.attach(AdHoc::on_ignite("Init CronManager", CronManager::init));
    }

    rocket_build
        .attach(cors::Cors)
        .attach(service_routing::router())
        .attach(modules_routing::router())
}
