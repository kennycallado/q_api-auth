use rocket::State;
use rocket::http::Status;
use serde::{Serialize, Deserialize};

use crate::app::providers::config_getter::ConfigGetter;
use crate::app::providers::models::message::PubNewToken;
use crate::app::providers::models::user::{PubNewUser, PubUserExpanded};
use crate::app::providers::services::claims::{Claims, UserInClaims};
use crate::app::providers::services::fetch::Fetch;

pub async fn create_guest(fetch: &State<Fetch>, project_id: i32) -> Result<UserInClaims, Status> {
    let robot_token = match Fetch::robot_token().await {
        Ok(token) => token,
        Err(_) => return Err(Status::InternalServerError),
    };

    let user_api_url = ConfigGetter::get_entity_url("user")
        .unwrap_or("http://localhost:8002/api/v1/user/".to_string());

    let new_user = PubNewUser {
        depends_on: 1,
        role_id: 4, // should be 6 to match guest
        active: Some(true),
        project_id,
    };

    let res;
    {
        let client = fetch.client.lock().await;
        res = client
            .post(&user_api_url)
            .header("Accept", "application/json")
            .header("Authorization", robot_token)
            .header("Content-Type", "application/json")
            .json(&new_user)
            .send()
            .await;
    }

    match res {
        Ok(res) => {
            if res.status() != 200 {
                return Err(Status::from_code(res.status().as_u16()).unwrap());
            }

            let user_exp = res.json::<PubUserExpanded>().await.unwrap();
            Ok(user_exp.into())
        }
        Err(_) => return Err(Status::InternalServerError),
    }

}

pub async fn delete_token(fetch: &State<Fetch>, user_id: i32) -> Result<Status, Status> {
    let robot_token = match Fetch::robot_token().await {
        Ok(token) => token,
        Err(_) => return Err(Status::InternalServerError),
    };

    let message_url = ConfigGetter::get_entity_url("message")
        .unwrap_or("http://localhost:8005/api/v1/messaging/".to_string())
        + "token/user/"
        + user_id.to_string().as_str();

    let res;
    {
        let client = fetch.client.lock().await;
        res = client
            .put(message_url)
            .header("Accept", "application/json")
            .header("Authorization", robot_token)
            .header("Content-Type", "application/json")
            .json(& PubNewToken { user_id, fcm_token: None, web_token: None })
            .send()
            .await;
    }

    match res {
        Ok(res) => {
            if res.status() != 200 {
                println!("Error: {}; trying to delete token from message", res.status().as_str());
                return Err(Status::from_code(res.status().as_u16()).unwrap());
            }

            Ok(Status::Ok)
        }
        Err(e) => {
            println!("Error: {};trying to delete token from message", e);
            return Err(Status::InternalServerError)},
    }
}

// pub async fn fcm_token_delete(fetch: &State<Fetch>, user_id: i32) -> Result<(), Status> {
//     #[derive(Serialize, Deserialize)]
//     struct NewFcmToken {
//         pub user_id: i32,
//         pub token: Option<String>,
//     }

//     let robot_token = match Fetch::robot_token().await {
//         Ok(token) => token,
//         Err(_) => return Err(Status::InternalServerError),
//     };

//     let fcm_api_url = ConfigGetter::get_entity_url("fcm")
//         .unwrap_or("http://localhost:8005/api/v1/fcm/".to_string())
//         + "token/"
//         + user_id.to_string().as_str()
//         + "/user";

//     let res;
//     {
//         let client = fetch.client.lock().await;
//         res = client
//             .put(&fcm_api_url)
//             .header("Accept", "application/json")
//             .header("Authorization", robot_token)
//             .header("Content-Type", "application/json")
//             .json(&NewFcmToken {
//                 user_id,
//                 token: None,
//             })
//             .send()
//             .await;
//     }

//     match res {
//         Ok(_) => Ok(()),
//         Err(_) => Err(Status::InternalServerError),
//     }
// }

pub async fn profile_request(fetch: &State<Fetch>, token: String) -> Result<i32, Status> {
    let robot_token = match Fetch::robot_token().await {
        Ok(token) => token,
        Err(_) => return Err(Status::InternalServerError),
    };

    let profile_api_url = ConfigGetter::get_entity_url("profile")
        .unwrap_or("http://localhost:8001/api/v1/profile/".to_string())
        + "token";

    let res;
    {
        let client = fetch.client.lock().await;
        res = client
            .post(&profile_api_url)
            .header("Accept", "application/json")
            .header("Authorization", robot_token)
            .header("Content-Type", "application/json")
            .json(&token)
            .send()
            .await;
    }

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
        .unwrap_or("http://localhost:8002/api/v1/user/".to_string())
        + user_id.to_string().as_str()
        + "/userinclaims";

    // Make the request
    let res;
    {
        let client = fetch.client.lock().await;
        res = client
            .get(&user_url)
            .header("Accept", "application/json")
            .header("Authorization", robot_token)
            .header("Content-Type", "application/json")
            .send()
            .await;
    }

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
