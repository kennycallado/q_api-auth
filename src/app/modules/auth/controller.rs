use rocket::State;
use rocket::http::{Cookie, CookieJar, Status};
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};

use crate::app::providers::guards::claims::RefreshClaims;
use crate::app::providers::services::fetch::Fetch;
use crate::app::providers::services::claims::UserInClaims;

use crate::app::modules::auth::services::helpers;

pub fn routes() -> Vec<rocket::Route> {
    routes![options_all, auth_bypass, auth, login, logout]
}

#[options("/<_..>")]
pub async fn options_all() -> Status {
    Status::Ok
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthUser {
    pub user: UserInClaims,
    pub access_token: String,
}

// WARNING: This is only for testing purposes
#[get("/bypass/<id>")]
pub async fn auth_bypass(fetch: &State<Fetch>, cookie: &CookieJar<'_>, id: i32) -> Result<Json<AuthUser>, Status> {
    let user_in_claims = helpers::user_request(fetch, id).await;
    if let Err(_) = user_in_claims {
        return Err(Status::InternalServerError);
    }
    let user_in_claims = user_in_claims.unwrap();

    let tokens = helpers::token_generator(user_in_claims.clone()).await;

    if let Err(_) = tokens {
        return Err(Status::NotFound);
    }
    let (access_token, refresh_token) = tokens.unwrap();

    cookie.add_private(Cookie::new("refresh_token", refresh_token));

    let auth_user = AuthUser {
        user: user_in_claims,
        access_token,
    };
    Ok(Json(auth_user))
}

#[get("/")]
pub async fn auth(fetch: &State<Fetch>, cookie: &CookieJar<'_>, claims: RefreshClaims) -> Result<Json<AuthUser>, Status> {
    let user_in_claims = helpers::user_request(fetch, claims.0.user.id).await;
    if let Err(_) = user_in_claims {
        return Err(Status::InternalServerError);
    }
    let user_in_claims = user_in_claims.unwrap();

    match helpers::token_generator(user_in_claims.clone()).await {
        Ok((refresh_token, access_token)) => {
            cookie.add_private(Cookie::new("refresh_token", refresh_token));

            let auth_user = AuthUser {
                user: user_in_claims,
                access_token,
            };

            Ok(Json(auth_user))
        }
        Err(e) => {
            return Err(e);
        }
    }
}

#[post("/login", data = "<token>")]
pub async fn login(fetch: &State<Fetch>, cookie: &CookieJar<'_>, token: Json<String>) -> Result<Json<AuthUser>, Status> {
    // Request the user_id from the profile api
    let token = token.into_inner();

    let mut guest = false;
    let project_id: i32;

    if token.contains("guest") && token.contains(".") {
        guest = true;
        let parts = token.split(".").collect::<Vec<&str>>();
        project_id = parts[1].parse::<i32>().unwrap();
    } else {
        project_id = 0;
    }

    let user_in_claims = if guest {
        match helpers::create_guest(fetch, project_id).await {
            Ok(user_in) => user_in,
            _ => return Err(Status::InternalServerError)
        }
    } else {
        let user_id = match helpers::profile_request(fetch, token).await {
            Ok(id) => id,
            _ => return Err(Status::Unauthorized)
        };

        match helpers::user_request(fetch, user_id).await {
            Ok(user) => user,
            _ => return Err(Status::InternalServerError)
        }
    };

    match helpers::token_generator(user_in_claims.clone()).await {
        Ok((refresh_token, access_token)) => {
            cookie.add_private(Cookie::new("refresh_token", refresh_token.clone()));

            let auth_user = AuthUser {
                user: user_in_claims,
                access_token,
            };

            Ok(Json(auth_user))
        }
        Err(e) => {
            return Err(e);
        }
    }
}

#[get("/logout")]
pub async fn logout(fetch: &State<Fetch>, cookie: &CookieJar<'_>, claims: RefreshClaims) -> Status {
    if let Err(_) = helpers::delete_token(fetch, claims.0.user.id).await {
        println!("AUTH: logout: fcm_token_delete failed");
    };

    match cookie.get_private("refresh_token") {
        Some(c) => {
            cookie.remove_private(c);
        },
        None => { }
    }

    Status::Ok
}
