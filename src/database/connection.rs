use rocket::{Build, Rocket};

#[cfg(feature = "db_diesel")]
use rocket_sync_db_pools::{database, diesel};

#[cfg(feature = "db_sqlx")]
use rocket_db_pools::{sqlx, Connection, Database};

#[cfg(feature = "db_diesel")]
#[database("questions")]
pub struct Db(pub diesel::PgConnection);

#[cfg(feature = "db_diesel")]
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

#[cfg(feature = "db_sqlx")]
#[derive(Database)]
#[database("questions")]
pub struct Db(pub sqlx::PgPool);

#[cfg(feature = "db_sqlx")]
pub async fn run_migrations(rocket: Rocket<Build>) -> Rocket<Build> {
    let db = Db::fetch(&rocket).expect("ERROR: database.run_migrations(); database connection");
    sqlx::migrate!("./src/database/migrations")
        .run(&**db)
        .await
        .expect("ERROR: database.run_migrations(); sqlx migrations");

    rocket
}
