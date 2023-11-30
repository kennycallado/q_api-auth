use rocket::request::{FromRequest, Outcome, Request};

use crate::app::providers::services::claims::{Claims, ClaimsError};
use crate::app::providers::services::token::Token;

pub struct AccessClaims(pub Claims);
pub struct RefreshClaims(pub Claims);

#[async_trait]
impl<'r> FromRequest<'r> for RefreshClaims {
    type Error = ClaimsError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token: Token = match Token::from_cookie(request) {
            Some(token) => token,
            None => {
                return Outcome::Error((
                    rocket::http::Status::BadRequest,
                    ClaimsError::MissingToken,
                ));
            }
        };

        let claims = match token.decode() {
            Ok(claims) => claims.claims,
            Err(e) => {
                println!("Error: {:?}", e);
                return Outcome::Error((
                    rocket::http::Status::Unauthorized,
                    ClaimsError::InvalidToken,
                ));
            }
        };

        Outcome::Success(RefreshClaims(claims))
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for AccessClaims {
    type Error = ClaimsError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = match Token::from_header(request) {
            Some(token) => token,
            None => return Outcome::Forward(rocket::http::Status::Ok), // ???
        };

        let claims = match token.decode() {
            Ok(claims) => claims.claims,
            Err(e) => {
                println!("Error: {:?}", e);
                return Outcome::Error((
                    rocket::http::Status::Unauthorized,
                    ClaimsError::InvalidToken,
                ));
            }
        };

        Outcome::Success(AccessClaims(claims))
    }
}
