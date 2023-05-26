use rocket::State;
use rocket::http::Status;
use serde::{Serialize, Deserialize};

use crate::app::providers::interfaces::helpers::claims::{Claims, UserInClaims};
use crate::app::providers::interfaces::helpers::config_getter::ConfigGetter;
use crate::app::providers::interfaces::helpers::fetch::Fetch;

pub async fn fcm_token_delete(fetch: &State<Fetch>, user_id: i32) -> Result<(), Status> {
    #[derive(Serialize, Deserialize)]
    struct NewFcmToken {
        pub user_id: i32,
        pub token: Option<String>,
    }

    let robot_token = match Fetch::robot_token().await {
        Ok(token) => token,
        Err(_) => return Err(Status::InternalServerError),
    };

    let fcm_api_url = ConfigGetter::get_entity_url("fcm")
        .unwrap_or("http://localhost:8005/api/v1/fcm".to_string())
        + "/token/"
        + user_id.to_string().as_str()
        + "/user";

    let client = fetch.client.lock().await;
    let res = client
        .put(&fcm_api_url)
        .header("Accept", "application/json")
        .header("Authorization", robot_token)
        .header("Content-Type", "application/json")
        .json(&NewFcmToken {
            user_id,
            token: None,
        })
        .send()
        .await;

    match res {
        Ok(_) => Ok(()),
        Err(_) => Err(Status::InternalServerError),
    }
}

pub async fn profile_request(fetch: &State<Fetch>, token: String) -> Result<i32, Status> {
    let robot_token = match Fetch::robot_token().await {
        Ok(token) => token,
        Err(_) => return Err(Status::InternalServerError),
    };

    let profile_api_url = ConfigGetter::get_entity_url("profile")
        .unwrap_or("http://localhost:8001/api/v1/profile".to_string())
        + "/token";

    let client = fetch.client.lock().await;
    let res = client
        .post(&profile_api_url)
        .header("Accept", "application/json")
        .header("Authorization", robot_token)
        .header("Content-Type", "application/json")
        .json(&token)
        .send()
        .await;

    match res {
        Ok(res) => {
            if res.status() != 200 {
                return Err(Status::from_code(res.status().as_u16()).unwrap());
            }

            Ok(res.json::<i32>().await.unwrap())
        }
        Err(_) => return Err(Status::InternalServerError),
    }
}

pub async fn user_request(fetch: &State<Fetch>, user_id: i32) -> Result<UserInClaims, Status> {
    // Prepare the robot token
    let robot_token = match Fetch::robot_token().await {
        Ok(token) => token,
        Err(_) => return Err(Status::InternalServerError),
    };

    // Prepare the url
    let user_url = ConfigGetter::get_entity_url("user")
        .unwrap_or("http://localhost:8002/api/v1/user".to_string())
        + "/"
        + user_id.to_string().as_str()
        + "/userinclaims";

    // Make the request
    let client = fetch.client.lock().await;
    let res = client
        .get(&user_url)
        .header("Accept", "application/json")
        .header("Authorization", robot_token)
        .header("Content-Type", "application/json")
        .send()
        .await;

    match res {
        Ok(res) => {
            if res.status() != 200 {
                return Err(Status::from_code(res.status().as_u16()).unwrap());
            }

            Ok(res.json::<UserInClaims>().await.unwrap())
        }
        Err(_) => return Err(Status::InternalServerError),
    }
}

pub async fn token_generator(user_in_claims: UserInClaims) -> Result<(String, String), Status> {
    let mut claims: Claims = Claims::from(user_in_claims);

    let refresh_token = claims.encode_for_refresh();
    if let Err(_) = refresh_token {
        return Err(Status::InternalServerError);
    }
    let refresh_token = refresh_token.unwrap();

    // encode_for_access removes claims.user.user_token
    let access_token = claims.encode_for_access();
    if let Err(_) = access_token {
        return Err(Status::InternalServerError);
    }
    let access_token = access_token.unwrap();

    Ok((refresh_token, access_token))
}
