use std::collections::{BTreeSet, HashMap};

use actix_web::{
    delete, get, post, put,
    web::{self, Data, Json, Path},
    HttpResponse, Responder,
};
use log::{log, Level};
use sha3::{Digest, Sha3_256};
use sqlx::{query, query_as, Postgres, Transaction};

use crate::{
    api::db::{log_query, log_query_as, open_transaction},
    app::AppState,
    auth::{CSHAuth, User},
    ldap,
    schema::api::{FetchParams, NewQuote, QuoteResponse, QuoteShardResponse},
    schema::{
        api::{NewReport, ReportResponse, ReportedQuoteResponse, ResolveParams, UserResponse},
        db::{QuoteShard, ReportedQuoteShard, ID},
    },
    utils::is_valid_username,
};

async fn shards_to_quotes(
    shards: &[QuoteShard],
    ldap: &ldap::client::LdapClient,
) -> Result<Vec<QuoteResponse>, HttpResponse> {
    let mut uid_map: HashMap<String, Option<String>> = HashMap::new();
    shards.iter().for_each(|x| {
        let _ = uid_map.insert(x.submitter.clone(), None);
        let _ = uid_map.insert(x.speaker.clone(), None);
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

    let mut quotes: Vec<QuoteResponse> = Vec::new();
    for shard in shards {
        let speaker = match uid_map.get(&shard.speaker).cloned().unwrap() {
            Some(cn) => UserResponse {
                uid: shard.speaker.clone(),
                cn,
            },
            None => continue,
        };
        if shard.index == 1 {
            let submitter = match uid_map.get(&shard.submitter).cloned().unwrap() {
                Some(cn) => UserResponse {
                    uid: shard.submitter.clone(),
                    cn,
                },
                None => continue,
            };
            quotes.push(QuoteResponse {
                id: shard.id,
                shards: vec![QuoteShardResponse {
                    body: shard.body.clone(),
                    speaker,
                }],
                timestamp: shard.timestamp,
                submitter,
            });
        } else {
            quotes.last_mut().unwrap().shards.push(QuoteShardResponse {
                body: shard.body.clone(),
                speaker,
            });
        }
    }
    Ok(quotes)
}

fn format_reports(quotes: &[ReportedQuoteShard]) -> Vec<ReportedQuoteResponse> {
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

async fn fetch_quotes(
    state: Data<AppState>,
    params: web::Query<FetchParams>,
    is_hidden: bool,
) -> impl Responder {
    let limit: i64 = params.limit.unwrap_or(10).into();
    let lt_qid: i32 = params.lt.unwrap_or(0);
    let query: String = params
        .q
        .clone()
        .map(|x| format!("%({})%", (x.replace(' ', "|"))))
        .unwrap_or("%%".into());
    let speaker = params.speaker.clone().unwrap_or("%".to_string());
    let submitter = params.submitter.clone().unwrap_or("%".to_string());
    match log_query_as(
        query_as!(
            QuoteShard,
            "SELECT pq.id as \"id!\", s.index as \"index!\", pq.submitter as \"submitter!\",
            pq.timestamp as \"timestamp!\", s.body as \"body!\", s.speaker as \"speaker!\"
            FROM (
                SELECT * FROM quotes q
                WHERE hidden = $6
                AND CASE WHEN $2::int4 > 0 THEN q.id < $2::int4 ELSE true END
                AND submitter LIKE $5
                AND q.id IN (
                    SELECT quote_id FROM shards s
                    WHERE LOWER(body) SIMILAR TO LOWER($3)
                    AND speaker LIKE $4
                )
                ORDER BY q.id DESC
                LIMIT $1
            ) AS pq
            LEFT JOIN shards s ON s.quote_id = pq.id
            ORDER BY timestamp DESC, pq.id DESC, s.index",
            limit,
            lt_qid,
            query,
            speaker,
            submitter,
            is_hidden,
        )
        .fetch_all(&state.db)
        .await,
        None,
    )
    .await
    {
        Ok((_, shards)) => match shards_to_quotes(shards.as_slice(), &state.ldap).await {
            Ok(quotes) => HttpResponse::Ok().json(quotes),
            Err(response) => response,
        },
        Err(res) => res,
    }
}

pub async fn hide_quote_by_id(
    id: i32,
    submitter: String,
    mut transaction: Transaction<'_, Postgres>,
) -> Result<Transaction<'_, Postgres>, HttpResponse> {
    match log_query_as(
        query!(
            "UPDATE quotes SET hidden=true WHERE id=$1 AND id IN (
                SELECT quote_id FROM shards s
                WHERE s.speaker = $2
            ) RETURNING id",
            id,
            submitter
        )
        .fetch_all(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, result)) => {
            if result.is_empty() {
                Err(HttpResponse::BadRequest()
                    .body("Either you are not quoted in this quote or this quote does not exist."))
            } else {
                log!(Level::Trace, "hid quote");
                Ok(tx.unwrap())
            }
        }
        Err(res) => Err(res),
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
    if body.shards.len() > 50 {
        return HttpResponse::BadRequest().body("Maximum of 50 shards exceeded.");
    }
    if body
        .shards
        .iter()
        .any(|x| !is_valid_username(x.speaker.as_str()))
    {
        return HttpResponse::BadRequest().body("Invalid speaker username format specified.");
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

    let ids: Vec<i32> = vec![id; body.shards.len()];
    let indices: Vec<i16> = (1..=body.shards.len()).map(|a| a as i16).collect();
    let bodies: Vec<String> = body.shards.iter().map(|s| s.body.clone()).collect();
    let speakers: Vec<String> = body.shards.iter().map(|s| s.speaker.clone()).collect();

    match log_query(
        query!("INSERT INTO Shards (quote_id, index, body, speaker) SELECT quote_id, index, body, speaker FROM UNNEST($1::int4[], $2::int2[], $3::text[], $4::varchar[]) as a(quote_id, index, body, speaker)", ids.as_slice(), indices.as_slice(), bodies.as_slice(), speakers.as_slice())
        .execute(&mut *transaction)
        .await
        .map(|_| ()), Some(transaction)).await {
        Ok(tx) => transaction = tx.unwrap(),
        Err(res) => return res,
    }

    log!(Level::Trace, "created quote shards");

    match transaction.commit().await {
        Ok(_) => HttpResponse::Ok().body(""),
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

    match log_query_as(
        query!(
            "DELETE FROM quotes WHERE id = $1 AND submitter = $2 RETURNING id",
            id,
            user.preferred_username
        )
        .fetch_all(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, result)) => {
            if result.is_empty() {
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
pub async fn hide_quote(state: Data<AppState>, path: Path<(i32,)>, user: User) -> impl Responder {
    let (id,) = path.into_inner();

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    match hide_quote_by_id(id, user.preferred_username, transaction).await {
        Ok(tx) => transaction = tx,
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

#[post("/quote/{id}/report", wrap = "CSHAuth::enabled()")]
pub async fn report_quote(
    state: Data<AppState>,
    path: Path<(i32,)>,
    body: Json<NewReport>,
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

    match log_query_as(
        query_as!(
            ID,
            "INSERT INTO reports (quote_id, reason, submitter_hash) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING id",
            id,
            body.reason,
            result.as_slice()
        )
        .fetch_all(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, ids)) => {
            transaction = tx.unwrap();
            if ids.is_empty() {
                return HttpResponse::BadRequest().body("You have already reported this quote.");
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
pub async fn get_quote(state: Data<AppState>, path: Path<(i32,)>) -> impl Responder {
    let (id,) = path.into_inner();

    match log_query_as(
        query_as!(
            QuoteShard,
            "SELECT pq.id as \"id!\", s.index as \"index!\", pq.submitter as \"submitter!\",
            pq.timestamp as \"timestamp!\", s.body as \"body!\", s.speaker as \"speaker!\"
            FROM (
                SELECT * FROM quotes q WHERE q.id = $1
            ) AS pq
            LEFT JOIN shards s ON s.quote_id = pq.id",
            id,
        )
        .fetch_all(&state.db)
        .await,
        None,
    )
    .await
    {
        Ok((_, shards)) => {
            if shards.is_empty() {
                HttpResponse::NotFound().body("Quote could not be found")
            } else {
                match shards_to_quotes(shards.as_slice(), &state.ldap).await {
                    Ok(quotes) => HttpResponse::Ok().json(quotes.get(0).unwrap()),
                    Err(res) => res,
                }
            }
        }
        Err(res) => res,
    }
}

#[get("/quotes", wrap = "CSHAuth::enabled()")]
pub async fn get_quotes(state: Data<AppState>, params: web::Query<FetchParams>) -> impl Responder {
    fetch_quotes(state, params, false).await
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
            ReportedQuoteShard,
            "SELECT pq.id AS \"quote_id!\", pq.submitter AS \"quote_submitter!\",
            pq.timestamp AS \"quote_timestamp!\", pq.hidden AS \"quote_hidden!\", 
            r.timestamp AS \"report_timestamp!\", r.id AS \"report_id!\",
            r.reason AS \"report_reason!\", r.resolver AS \"report_resolver\"
            FROM (
                SELECT * FROM quotes q
                WHERE q.id IN (
                    SELECT quote_id FROM reports r
                    WHERE r.resolver IS NULL
                )
            ) AS pq
            LEFT JOIN reports r ON r.quote_id = pq.id WHERE r.resolver IS NULL
            ORDER BY pq.id, r.id"
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

#[get("/hidden", wrap = "CSHAuth::admin_only()")]
pub async fn get_hidden(state: Data<AppState>, params: web::Query<FetchParams>) -> impl Responder {
    fetch_quotes(state, params, true).await
}

#[put("/quote/{id}/resolve", wrap = "CSHAuth::admin_only()")]
pub async fn resolve_report(
    state: Data<AppState>,
    path: Path<(i32,)>,
    user: User,
    params: web::Query<ResolveParams>,
) -> impl Responder {
    let (id,) = path.into_inner();

    let mut transaction = match open_transaction(&state.db).await {
        Ok(t) => t,
        Err(res) => return res,
    };

    match log_query_as(
        query_as!(
            ID,
            "UPDATE reports SET resolver=$1 WHERE quote_id=$2 AND resolver IS NULL RETURNING id",
            user.preferred_username,
            id,
        )
        .fetch_all(&mut *transaction)
        .await,
        Some(transaction),
    )
    .await
    {
        Ok((tx, ids)) => {
            transaction = tx.unwrap();
            if ids.is_empty() {
                return HttpResponse::BadRequest()
                    .body("Report is either already resolved or doesn't exist.");
            }
        }
        Err(res) => return res,
    }

    log!(Level::Trace, "resolved all quote's reports");

    if let Some(true) = params.hide {
        match hide_quote_by_id(id, user.preferred_username, transaction).await {
            Ok(tx) => transaction = tx,
            Err(res) => return res,
        }
    }

    match transaction.commit().await {
        Ok(_) => HttpResponse::Ok().body(""),
        Err(e) => {
            log!(Level::Error, "Transaction failed to commit");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}
