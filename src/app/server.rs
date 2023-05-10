// use rocket::fairing::AdHoc;

use crate::config::cors;
// use crate::config::database;

use super::modules::routing as modules_routing;
// use super::providers::interfaces::helpers::config_getter::ConfigGetter;
use super::routing as service_routing;

#[launch]
pub fn rocket() -> _ {
    // let mut rocket_build = rocket::build();
    let rocket_build = rocket::build();

    // Only attach the database if migrations_run is true
    // if ConfigGetter::get_migrations_run().unwrap_or(false) {
    //     rocket_build = rocket_build
    //         .attach(database::Db::fairing())
    //         .attach(AdHoc::on_ignite(
    //             "Diesel Migrations",
    //             database::run_migrations,
    //         ));
    // }

    rocket_build
        .attach(cors::Cors)
        .attach(service_routing::router())
        .attach(modules_routing::router())
}
