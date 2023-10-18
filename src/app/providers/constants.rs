#![allow(unused)]

pub const ACCESS_TOKEN_EXPIRATION: i64 = 60 * 60 * 24; // 1 day
pub const REFRESH_TOKEN_EXPIRATION: i64 = ACCESS_TOKEN_EXPIRATION * 7; // 7 day
pub const ROBOT_TOKEN_EXPIRATION: i64 = 60 * 5; // 5 minutes
