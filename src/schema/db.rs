use serde::{Deserialize, Serialize};
use sqlx::FromRow;
pub struct ID {
    pub id: i32, // SERIAL value
}

#[derive(Serialize, Deserialize, Debug, FromRow)]
pub struct Shard {
    pub quote_id: i32,
    pub index: i32,
    pub body: String,
    pub speaker: String,
}

#[derive(Serialize, Deserialize, Debug, FromRow)]
pub struct Quote {
    pub id: i32,
    pub shards: sqlx::types::Json<Vec<Shard>>,
    pub submitter: String,
    pub timestamp: chrono::NaiveDateTime,
    pub hidden_reason: Option<String>,
    pub hidden_actor: Option<String>,
    pub vote: Option<Vote>,
    pub score: i64,
    pub favorited: bool,
}

#[derive(Serialize, Debug)]
pub struct ReportedQuote {
    pub quote_id: i32,
    pub report_id: i32,
    pub report_reason: String,
    pub report_timestamp: chrono::NaiveDateTime,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "vote", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Vote {
    Upvote,
    Downvote,
}
