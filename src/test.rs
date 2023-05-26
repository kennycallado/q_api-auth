use crate::app::server::rocket;
use rocket::http::{Accept, ContentType, Status};

#[rocket::async_test]
async fn test_health() {
    use rocket::local::asynchronous::Client;

    let client = Client::tracked(rocket().await).await.unwrap();
    let response = client
        .get("/health")
        .header(Accept::JSON)
        // .header(Header::new("Authorization", format!("Bearer {bearer}")))
        .header(ContentType::JSON)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().await, Some("OK".into()));
}
