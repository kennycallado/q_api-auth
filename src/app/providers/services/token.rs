use jsonwebtoken::errors::Error;
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation};
use rocket::http::Cookie;
use rocket::Request;

use crate::app::providers::config_getter::ConfigGetter;
use crate::app::providers::services::claims::Claims;

#[derive(Debug)]
pub struct Token(pub String);

impl Token {
    pub fn from_header(request: &Request<'_>) -> Option<Token> {
        let token = request.headers().get_one("Authorization")?;

        let token = token.replace("Bearer ", "");
        Some(Token(token))
    }

    pub fn from_cookie(request: &Request<'_>) -> Option<Token> {
        let token = request.cookies().get_private("refresh_token")?;

        request.cookies().remove_private(token.clone());

        let token = token.value().to_string();
        Some(Token(token))
    }

    pub fn decode(&self) -> Result<TokenData<Claims>, Error> {
        let secret_key = match ConfigGetter::get_secret_key() {
            None => panic!("secret_key is mandatory"),
            Some(secret_key) => secret_key,
        };

        decode::<Claims>(
            &self.0,
            &DecodingKey::from_secret(secret_key.as_ref()),
            &Validation::default(),
        )
    }
}
