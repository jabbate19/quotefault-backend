use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Display};

use actix_web::body::MessageBody;
use actix_web::{
    delete, get,
    http::StatusCode,
    post, put,
    web::{self, Data, Json, Path},
    HttpResponse, Responder, ResponseError,
};
use log::{log, Level};
use sha3::{Digest, Sha3_256};
use sqlx::{query, query_as, Connection, Postgres, QueryBuilder, Transaction};

use crate::{
    api::{
        db::{log_query, log_query_as, open_transaction},
        pings::send_ping,
    },
    app::AppState,
    auth::{CSHAuth, User, SECURITY_ENABLED},
    ldap,
    schema::{
        api::{
            FetchParams, Hidden, NewQuote, QuoteResponse, QuoteShardResponse, Reason,
            ReportResponse, ReportedQuoteResponse, ResolveParams, UserResponse, VersionResponse,
            VoteParams,
        },
        db::{ReportedQuote, Quote, Vote, ID},
    },
    utils::is_valid_username,
};

async fn populate_user_data(
    quotes: &[Quote],
    ldap: &ldap::client::LdapClient,
) -> Result<Vec<QuoteResponse>, HttpResponse> {
    let mut uid_map: HashMap<String, Option<String>> = HashMap::new();
    quotes.iter().for_each(|x| {
        x.shards.iter().for_each(|s| {
            uid_map.insert(x.submitter.clone(), None);
            uid_map.insert(s.speaker.clone(), None);
        });
        if let Some(hidden_actor) = &x.hidden_actor {
            uid_map.insert(hidden_actor.clone(), None);
        }
    });
    match ldap::get_users(
        ldap,
        uid_map.keys().cloned().collect::<Vec<String>>().as_slice(),
    )
    .await
    {
        Ok(users) => users.into_iter().for_each(|x| {
            let _ = uid_map.insert(x.uid, Some(x.cn));
        }),
        Err(err) => return Err(HttpResponse::InternalServerError().body(err.to_string())),
    }

    Ok(quotes
        .iter()
        .map(|quote| QuoteResponse {
            id: quote.id,
            submitter: UserResponse {
                uid: quote.submitter.clone(),
                cn: uid_map
                    .get(&quote.submitter)
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .to_string(),
            },
            timestamp: quote.timestamp,
            score: quote.score,
            vote: quote.vote.clone(),
            hidden: quote.hidden_actor.as_ref().map(|actor| Hidden {
                reason: quote.hidden_reason.as_ref().unwrap().to_string(),
                actor: UserResponse {
                    uid: actor.to_string(),
                    cn: uid_map
                        .get(actor)
                        .as_ref()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .to_string(),
                },
            }),
            favorited: quote.favorited,
            shards: quote
                .shards
                .iter()
                .map(|s| QuoteShardResponse {
                    speaker: UserResponse {
                        uid: s.speaker.clone(),
                        cn: uid_map
                            .get(&s.speaker)
                            .as_ref()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .to_string(),
                    },
                    body: s.body.clone(),
                })
                .collect(),
        })
        .collect())
}

fn format_reports(quotes: &[ReportedQuote]) -> Vec<ReportedQuoteResponse> {
    let mut reported_quotes: HashMap<i32, ReportedQuoteResponse> = HashMap::new();
    for quote in quotes {
        match reported_quotes.get_mut(&quote.quote_id) {
            Some(reported_quote) => reported_quote.reports.push(ReportResponse {
                reason: quote.report_reason.clone(),
                timestamp: quote.report_timestamp,
                id: quote.report_id,
            }),
            None => {
                let _ = reported_quotes.insert(
                    quote.quote_id,
                    ReportedQuoteResponse {
                        quote_id: quote.quote_id,
                        reports: vec![ReportResponse {
                            timestamp: quote.report_timestamp,
                            reason: quote.report_reason.clone(),
                            id: quote.report_id,
                        }],
                    },
                );
            }
        }
    }
    reported_quotes.into_values().collect()
}

impl ResponseError for SqlxErrorOrResponse<'_> {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::SqlxError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ResponseOwned(status_code, _) | Self::Response(status_code, _) => *status_code,
        }
    }
    fn error_response(&self) -> HttpResponse {
        match self {
            Self::SqlxError(error) => {
                HttpResponse::InternalServerError().body(format!("SQLX Error: {error}"))
            }
            Self::Response(status_code, body) => {
                HttpResponse::with_body(*status_code, body.to_string().boxed())
            }
            Self::ResponseOwned(status_code, body) => {
                HttpResponse::with_body(*status_code, body.clone().boxed())
            }
        }
    }
}

impl Display for SqlxErrorOrResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::SqlxError(error) => write!(f, "{error}"),
            Self::Response(status_code, error_message) => {
                write!(f, "{status_code}: {error_message}")
            }
            Self::ResponseOwned(status_code, error_message) => {
                write!(f, "{status_code}: {error_message}")
            }
        }
    }
}

#[derive(Debug)]
pub enum SqlxErrorOrResponse<'a> {
    SqlxError(sqlx::Error),
    Response(StatusCode, &'a str),
    ResponseOwned(StatusCode, String),
}

pub async fn hide_quote_by_id(
    id: i32,
    user: User,
    reason: String,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), SqlxErrorOrResponse<'static>> {
    let result = query!(
        "INSERT INTO public.hidden(quote_id, reason, actor)
            SELECT $1, $2, $3::varchar
            WHERE $1 IN (SELECT id FROM quotes)
                AND ($4 OR $1 IN (
                    SELECT quote_id FROM shards s
                    WHERE s.speaker = $3
                ))",
        id,
        reason,
        user.preferred_username,
        user.admin() || !*SECURITY_ENABLED,
    )
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 0 {
        Err(SqlxErrorOrResponse::Response(
            StatusCode::BAD_REQUEST,
            "Either you are not quoted in this quote or this quote does not exist.",
        ))
    } else {
        log!(Level::Trace, "hid quote");
        Ok(())
    }
}

#[post("/quote", wrap = "CSHAuth::enabled()")]
pub async fn create_quote(
    state: Data<AppState>,
    body: Json<NewQuote>,
    user: User,
) -> impl Responder {
    log!(Level::Info, "POST /api/quote");

    if body.shards.is_empty() {
        return HttpResponse::BadRequest().body("No quote shards specified");
    }
    if body.shards.len() > 6 {
        return HttpResponse::BadRequest().body("Maximum of 6 shards exceeded.");
    }
    for shard in &body.shards {
        if !is_valid_username(shard.speaker.as_str()) {
            return HttpResponse::BadRequest().body("Invalid speaker username format specified.");
        }
        if user.preferred_username == shard.speaker {
            return HttpResponse::BadRequest().body("Erm... maybe don't quote yourself?");
        }
    }
    if !is_valid_username(user.preferred_username.as_str()) {
        return HttpResponse::BadRequest()
            .body("Invalid submitter username specified. SHOULD NEVER HAPPEN!");
    }
    let mut users: Vec<String> = body.shards.iter().map(|x| x.speaker.clone()).collect();
    users.push(user.preferred_username.clone());
    match ldap::users_exist(&state.ldap, BTreeSet::from_iter(users.into_iter())).await {
        Ok(exists) => {
            if !exists {
                return HttpResponse::BadRequest().body("Some users submitted do not exist.");
            }
        }
        Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
    }

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    let id: i32;
    match log_query_as(
        query_as!(
            ID,
            "INSERT INTO quotes(submitter) VALUES ($1) RETURNING id",
            user.preferred_username
        )
        .fetch_all(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, i)) => {
            transaction = tx.unwrap();
            id = i[0].id;
        }
        Err(res) => return res,
    }
    log!(Level::Trace, "created a new entry in quote table");

    let shards = body
        .shards
        .iter()
        .enumerate()
        .map(|(i, s)| (id, i as i32, s.body.clone(), s.speaker.clone()));

    let mut sql_query = QueryBuilder::new("INSERT INTO Shards (quote_id, index, body, speaker) ");

    sql_query.push_values(shards, |mut b, shard| {
        b.push_bind(shard.0)
            .push_bind(shard.1)
            .push_bind(shard.2)
            .push_bind(shard.3);
    });

    match log_query(
        sql_query.build().execute(&mut *transaction).await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, _)) => transaction = tx.unwrap(),
        Err(res) => return res,
    }

    log!(Level::Trace, "created quote shards");

    match transaction.commit().await {
        Ok(_) => {
            for shard in &body.shards {
                if let Err(err) = send_ping(
                    shard.speaker.clone(),
                    format!(
                        "You were quoted by {}. Check it out at Quotefault!",
                        user.preferred_username
                    ),
                ) {
                    log!(Level::Error, "Failed to ping: {}", err);
                }
            }
            HttpResponse::Ok().body("")
        }
        Err(e) => {
            log!(Level::Error, "Transaction failed to commit");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

#[delete("/quote/{id}", wrap = "CSHAuth::enabled()")]
pub async fn delete_quote(state: Data<AppState>, path: Path<(i32,)>, user: User) -> impl Responder {
    let (id,) = path.into_inner();

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    match log_query(
        query!(
            "DELETE FROM quotes WHERE id = $1 AND (submitter = $2 OR $3)",
            id,
            user.preferred_username,
            user.admin() || !*SECURITY_ENABLED
        )
        .execute(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, result)) => {
            if result.rows_affected() == 0 {
                return HttpResponse::BadRequest()
                    .body("Either this is not your quote or this quote does not exist.");
            }
            transaction = tx.unwrap()
        }
        Err(res) => return res,
    }

    log!(Level::Trace, "deleted quote and all shards");

    match transaction.commit().await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(e) => {
            log!(Level::Error, "Transaction failed to commit");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

#[put("/quote/{id}/hide", wrap = "CSHAuth::enabled()")]
pub async fn hide_quote(
    state: Data<AppState>,
    path: Path<(i32,)>,
    user: User,
    Json(reason): Json<Reason>,
) -> Result<HttpResponse, SqlxErrorOrResponse<'static>> {
    let (id,) = path.into_inner();

    if reason.reason.len() < 10 {
        return Err(SqlxErrorOrResponse::Response(
            StatusCode::BAD_REQUEST,
            "Reason must be at least 10 characters",
        ));
    }

    state
        .db
        .acquire()
        .await?
        .transaction(|transaction| {
            Box::pin(async move { hide_quote_by_id(id, user, reason.reason, transaction).await })
        })
        .await?;
    Ok(HttpResponse::Ok().body(""))
}

#[post("/quote/{id}/report", wrap = "CSHAuth::enabled()")]
pub async fn report_quote(
    state: Data<AppState>,
    path: Path<(i32,)>,
    body: Json<Reason>,
    user: User,
) -> impl Responder {
    let (id,) = path.into_inner();

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    let mut hasher = Sha3_256::new();
    hasher.update(format!("{}coleandethanwerehere", user.preferred_username).as_str()); // >:)
    let result = hasher.finalize();

    match log_query(
        query!(
            "INSERT INTO reports (quote_id, reason, submitter_hash)
            SELECT $1, $2, $3
            WHERE $1 IN (
                SELECT id FROM quotes
                WHERE id NOT IN (SELECT quote_id FROM hidden)
            )
            ON CONFLICT DO NOTHING",
            id,
            body.reason,
            result.as_slice()
        )
        .execute(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, result)) => {
            transaction = tx.unwrap();
            if result.rows_affected() == 0 {
                return HttpResponse::BadRequest()
                    .body("You have already reported this quote or quote does not exist");
            }
        }
        Err(res) => return res,
    };
    log!(Level::Trace, "created a new report");

    match transaction.commit().await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(e) => {
            log!(Level::Error, "Transaction failed to commit");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

#[get("/quote/{id}", wrap = "CSHAuth::enabled()")]
pub async fn get_quote(state: Data<AppState>, path: Path<(i32,)>, user: User) -> impl Responder {
    let (id,) = path.into_inner();

    let mut sql_query = QueryBuilder::new(
        "SELECT quotes.id as \"id\",
            json_agg(shards.*) as \"shards\",
            quotes.submitter as \"submitter\",
            quotes.timestamp as \"timestamp\",
            hidden.reason as \"hidden_reason\",
            hidden.actor as \"hidden_actor\",
            uservote.vote as \"vote\",
            COUNT(DISTINCT upvotes.*) - COUNT(DISTINCT downvotes.*) AS \"score\",
            COUNT(DISTINCT favorites.*) > 0 AS \"favorited\"
            FROM quotes
            JOIN shards ON quotes.id = shards.quote_id
            LEFT JOIN hidden ON quotes.id = hidden.quote_id
            LEFT JOIN votes upvotes ON quotes.id = upvotes.quote_id AND upvotes.vote = 'upvote'
            LEFT JOIN votes downvotes ON quotes.id = upvotes.quote_id AND upvotes.vote = 'downvote'
            LEFT JOIN votes uservote ON quotes.id = uservote.quote_id and uservote.submitter = ",
    );
    sql_query.push_bind(&user.preferred_username);
    sql_query
        .push("LEFT JOIN favorites ON quotes.id = favorites.quote_id AND favorites.username = ");
    sql_query.push_bind(&user.preferred_username);
    sql_query.push("WHERE quotes.id = ");
    sql_query.push_bind(id);
    sql_query.push("GROUP by quotes.id, hidden.reason, hidden.actor, uservote.vote");

    match log_query_as(
        sql_query
            .build_query_as::<Quote>()
            .fetch_all(&state.db)
            .await,
        None,
    )
    .await
    {
        Ok((_, mut quote_vec)) => match quote_vec.pop() {
            Some(quote) => {
                if quote.hidden_actor.is_some() && (!user.admin() && *SECURITY_ENABLED) {
                    return HttpResponse::Unauthorized().body("This quote is hidden");
                }
                match populate_user_data(&Vec::from([quote]), &state.ldap).await {
                    Ok(resp_data) => HttpResponse::Ok().json(resp_data.first().unwrap()),
                    Err(res) => res,
                }
            }
            None => HttpResponse::NotFound().body("Quote could not be found"),
        },
        Err(res) => res,
    }
}

#[post("/quote/{id}/vote", wrap = "CSHAuth::enabled()")]
pub async fn vote_quote(
    state: Data<AppState>,
    path: Path<(i32,)>,
    params: web::Query<VoteParams>,
    user: User,
) -> impl Responder {
    let (id,) = path.into_inner();
    let vote = params.vote.clone();

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    match log_query(
        query!(
            "INSERT INTO votes (quote_id, vote, submitter)
            SELECT $1, $2, $3
            WHERE $1 IN (
                SELECT id FROM quotes
                WHERE CASE WHEN $4 THEN true ELSE id NOT IN (SELECT quote_id FROM hidden) END
            )
            ON CONFLICT (quote_id, submitter)
            DO UPDATE SET vote=$2",
            id,
            vote as Vote,
            user.preferred_username,
            user.admin() || !*SECURITY_ENABLED
        )
        .execute(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, result)) => {
            transaction = tx.unwrap();
            if result.rows_affected() == 0 {
                return HttpResponse::BadRequest().body("Quote does not exist");
            }
        }
        Err(res) => return res,
    }

    match transaction.commit().await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(e) => {
            log!(Level::Error, "Transaction failed to commit");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

#[delete("/quote/{id}/vote", wrap = "CSHAuth::enabled()")]
pub async fn unvote_quote(state: Data<AppState>, path: Path<(i32,)>, user: User) -> impl Responder {
    let (id,) = path.into_inner();

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    match log_query(
        query!(
            "DELETE FROM votes 
            WHERE quote_id=$1 AND submitter=$2
            AND $1 IN (
                SELECT id FROM quotes
                WHERE CASE WHEN $3 THEN true ELSE id NOT IN (SELECT quote_id FROM hidden) END
            )",
            id,
            user.preferred_username,
            user.admin() || !*SECURITY_ENABLED
        )
        .execute(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, result)) => {
            transaction = tx.unwrap();
            if result.rows_affected() == 0 {
                return HttpResponse::BadRequest().body("Quote does not exist");
            }
        }
        Err(res) => return res,
    }

    match transaction.commit().await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(e) => {
            log!(Level::Error, "Transaction failed to commit");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

#[get("/quotes", wrap = "CSHAuth::enabled()")]
pub async fn get_quotes(
    state: Data<AppState>,
    params: web::Query<FetchParams>,
    user: User,
) -> impl Responder {
    let limit: i64 = params
        .limit
        .map(|x| if x == -1 { i64::MAX } else { x })
        .unwrap_or(10);
    let mut sql_query = QueryBuilder::new(
        "SELECT quotes.id as \"id\",
            json_agg(shards.*) as \"shards\",
            quotes.submitter as \"submitter\",
            quotes.timestamp as \"timestamp\",
            hidden.reason as \"hidden_reason\",
            hidden.actor as \"hidden_actor\",
            uservote.vote as \"vote\",
            COUNT(DISTINCT upvotes.*) - COUNT(DISTINCT downvotes.*) AS \"score\",
            COUNT(DISTINCT favorites.*) > 0 AS \"favorited\"
            FROM quotes
            JOIN shards ON quotes.id = shards.quote_id
            LEFT JOIN hidden ON quotes.id = hidden.quote_id
            LEFT JOIN votes upvotes ON quotes.id = upvotes.quote_id AND upvotes.vote = 'upvote'
            LEFT JOIN votes downvotes ON quotes.id = upvotes.quote_id AND upvotes.vote = 'downvote'
            LEFT JOIN votes uservote ON quotes.id = uservote.quote_id and uservote.submitter = ",
    );
    sql_query.push_bind(&user.preferred_username);
    sql_query
        .push("LEFT JOIN favorites ON quotes.id = favorites.quote_id AND favorites.username = ");
    sql_query.push_bind(&user.preferred_username);
    sql_query.push("WHERE 1=1");
    if let Some(lt) = params.lt {
        sql_query.push("AND quotes.id < ");
        sql_query.push_bind(lt);
    }
    if let Some(query) = &params.q {
        sql_query.push("AND shards.body LIKE ");
        sql_query.push_bind(format!("%{query}%"));
    }
    if let Some(speaker) = &params.speaker {
        sql_query.push("AND shards.speaker = ");
        sql_query.push_bind(speaker);
    }
    if let Some(submitter) = &params.submitter {
        sql_query.push("AND quotes.submitter = ");
        sql_query.push_bind(submitter);
    }
    if let Some(involved) = &params.involved {
        sql_query.push("AND (quotes.submitter = ");
        sql_query.push_bind(involved);
        sql_query.push("OR shards.speaker = ");
        sql_query.push_bind(involved);
        sql_query.push(")");
    }
    match params.hidden {
        Some(true) => {
            sql_query.push("AND hidden.reason IS NOT NULL");
            if !user.admin() && *SECURITY_ENABLED {
                sql_query.push("AND (submitter =");
                sql_query.push_bind(&user.preferred_username);
                sql_query.push("OR submitter = ");
                sql_query.push_bind(&user.preferred_username);
                sql_query.push(")");
            }
        }
        Some(false) => {
            sql_query.push("AND hidden.reason IS NULL");
        }
        None => {}
    }
    match params.favorited {
        Some(true) => {
            sql_query.push("AND COUNT(favorites.*) = 1");
        }
        Some(false) => {
            sql_query.push("AND COUNT(favorites.*) = 0");
        }
        None => {}
    }
    sql_query.push(
        "GROUP by quotes.id, hidden.reason, hidden.actor, uservote.vote
			ORDER BY quotes.id DESC
			LIMIT ",
    );
    sql_query.push_bind(limit);
    match log_query_as(
        sql_query
            .build_query_as::<Quote>()
            .fetch_all(&state.db)
            .await,
        None,
    )
    .await
    {
        Ok((_, data)) => HttpResponse::Ok().json(data),
        Err(res) => res,
    }
}

#[get("/users", wrap = "CSHAuth::enabled()")]
pub async fn get_users(state: Data<AppState>) -> impl Responder {
    match ldap::get_group_members(&state.ldap, "member").await {
        Ok(users) => HttpResponse::Ok().json(
            users
                .into_iter()
                .map(|x| UserResponse {
                    uid: x.uid,
                    cn: x.cn,
                })
                .collect::<Vec<_>>(),
        ),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[get("/reports", wrap = "CSHAuth::admin_only()")]
pub async fn get_reports(state: Data<AppState>) -> impl Responder {
    match log_query_as(
        query_as!(
            ReportedQuote,
            "SELECT quotes.id AS \"quote_id!\",
            reports.timestamp AS \"report_timestamp!\", reports.id AS \"report_id!\",
            reports.reason AS \"report_reason!\"
            FROM quotes
            LEFT JOIN reports ON reports.quote_id = quotes.id
            WHERE reports.resolver IS NULL
            ORDER BY quotes.id, reports.id"
        )
        .fetch_all(&state.db)
        .await,
        None,
    )
    .await
    {
        Ok((_, reports)) => HttpResponse::Ok().json(format_reports(reports.as_slice())),
        Err(res) => res,
    }
}

impl From<sqlx::Error> for SqlxErrorOrResponse<'_> {
    fn from(error: sqlx::Error) -> Self {
        Self::SqlxError(error)
    }
}

#[put("/quote/{id}/resolve", wrap = "CSHAuth::admin_only()")]
pub async fn resolve_report(
    state: Data<AppState>,
    path: Path<(i32,)>,
    user: User,
    params: web::Query<ResolveParams>,
) -> Result<HttpResponse, SqlxErrorOrResponse<'static>> {
    let (id,) = path.into_inner();

    state.db.acquire().await?.transaction(|transaction| Box::pin(async move {

        let result = match query!(
            "UPDATE reports SET resolver=$1 WHERE quote_id=$2 AND resolver IS NULL RETURNING reason",
            user.preferred_username,
            id,
        )
            .fetch_one(&mut **transaction)
            .await {
                Ok(result) => result,
                Err(sqlx::Error::RowNotFound) =>
                {
                    return Err(SqlxErrorOrResponse::Response(StatusCode::BAD_REQUEST, "Report is either already resolved or doesn't exist."));
                },
                Err(err) => return Err(err.into()),
            };

        log!(Level::Trace, "resolved all quote's reports");

        if let Some(true) = params.hide {
            hide_quote_by_id(id, user, result.reason, &mut *transaction).await?;
        }

        Ok(())

    })).await?;

    Ok(HttpResponse::Ok().body(""))
}

#[post("/quote/{id}/favorite", wrap = "CSHAuth::enabled()")]
pub async fn favorite_quote(
    state: Data<AppState>,
    user: User,
    path: Path<(i32,)>,
) -> impl Responder {
    let (id,) = path.into_inner();

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    match log_query(
        query!(
            "INSERT INTO favorites (quote_id, username)
            VALUES ($1, $2)",
            id,
            user.preferred_username,
        )
        .execute(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, result)) => {
            transaction = tx.unwrap();
            if result.rows_affected() == 0 {
                return HttpResponse::BadRequest()
                    .body("Quote is either already favorited or doesn't exist.");
            }
        }
        Err(res) => return res,
    }

    match transaction.commit().await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(e) => {
            log!(Level::Error, "Transaction failed to commit");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

#[delete("/quote/{id}/favorite", wrap = "CSHAuth::enabled()")]
pub async fn unfavorite_quote(
    state: Data<AppState>,
    user: User,
    path: Path<(i32,)>,
) -> impl Responder {
    let (id,) = path.into_inner();

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    match log_query(
        query!(
            "DELETE FROM favorites WHERE quote_id=$1 AND username=$2",
            id,
            user.preferred_username,
        )
        .execute(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, result)) => {
            transaction = tx.unwrap();
            if result.rows_affected() == 0 {
                return HttpResponse::BadRequest().body("Quote is not favorited.");
            }
        }
        Err(res) => return res,
    }

    match transaction.commit().await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(e) => {
            log!(Level::Error, "Transaction failed to commit");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

#[get("/version", wrap = "CSHAuth::enabled()")]
pub async fn get_version() -> impl Responder {
    HttpResponse::Ok().json(VersionResponse {
        build_date: env!("VERGEN_BUILD_TIMESTAMP").to_string(),
        date: env!("VERGEN_GIT_COMMIT_TIMESTAMP").to_string(),
        revision: env!("VERGEN_GIT_SHA").to_string(),
        url: env!("REPO_URL").to_string(),
    })
}
