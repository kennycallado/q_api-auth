#[cfg(feature = "db")]
use rocket::{Build, Rocket};
#[cfg(feature = "db")]
use rocket_sync_db_pools::{database, diesel};

#[cfg(feature = "db")]
#[database("questions")]
pub struct Db(diesel::PgConnection);

#[cfg(feature = "db")]
pub async fn run_migrations(rocket: Rocket<Build>) -> Rocket<Build> {
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};

    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("src/database/migrations");

    Db::get_one(&rocket)
        .await
        .expect("ERROR: database.run_migrations(); database connection")
        .run(|conn| {
            conn.run_pending_migrations(MIGRATIONS)
                .expect("ERROR: database.run_migrations(); diesel migrations");
        })
        .await;

    rocket
}
