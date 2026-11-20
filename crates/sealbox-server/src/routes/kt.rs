//! Key-transparency log endpoints (gate G30, `docs/IDENTITY.md`).
//!
//! * `GET /v1/kt/key` → `{algorithm:"ed25519", public_key:<hex>}`
//! * `GET /v1/kt/sth` → `{tree_size, root_hash:<hex>, timestamp, signature:<base64>}`
//! * `GET /v1/kt/proof/by-email/{email}[?tree_size=N]` → `{tree_size, leaf_index, entry,
//!   leaf_hash, audit_path:[hex], sth}`: the newest entry for the address within the tree of
//!   size N (default: the latest head) and its inclusion proof against that head; 404 if the
//!   address never appeared.
//! * `GET /v1/kt/consistency?from=M[&to=N]` → `{from, to, proof:[hex]}`
//! * `GET /v1/kt/entries[?start=0&limit=100]` → `{tree_size, start, entries:[{index, entry,
//!   leaf_hash}]}` (limit ≤ 1000)

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, AppResult},
    kt::{self, Entry, Sth},
    openpgp,
    state::AppState,
};

#[derive(Serialize)]
pub struct KeyResponse {
    pub algorithm: &'static str,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct ProofResponse {
    pub tree_size: u64,
    pub leaf_index: u64,
    pub entry: Entry,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
    pub sth: Sth,
}

#[derive(Serialize)]
pub struct ConsistencyResponse {
    pub from: u64,
    pub to: u64,
    pub proof: Vec<String>,
}

#[derive(Serialize)]
pub struct IndexedEntry {
    pub index: u64,
    pub entry: Entry,
    pub leaf_hash: String,
}

#[derive(Serialize)]
pub struct EntriesResponse {
    pub tree_size: u64,
    pub start: u64,
    pub entries: Vec<IndexedEntry>,
}

#[derive(Deserialize)]
pub struct ProofQuery {
    pub tree_size: Option<u64>,
}

#[derive(Deserialize)]
pub struct ConsistencyQuery {
    pub from: u64,
    pub to: Option<u64>,
}

#[derive(Deserialize)]
pub struct EntriesQuery {
    pub start: Option<u64>,
    pub limit: Option<u64>,
}

/// `GET /v1/kt/key`
pub async fn key(State(state): State<AppState>) -> AppResult<Json<KeyResponse>> {
    let public_key = state
        .db()
        .call(|c| kt::public_key_hex(c).map_err(AppError::from))
        .await?;
    Ok(Json(KeyResponse {
        algorithm: "ed25519",
        public_key,
    }))
}

/// `GET /v1/kt/sth`
pub async fn sth(State(state): State<AppState>) -> AppResult<Json<Sth>> {
    let sth = state
        .db()
        .call(|c| kt::latest_sth(c).map_err(AppError::from))
        .await?;
    Ok(Json(sth))
}

/// `GET /v1/kt/proof/by-email/{email}`
pub async fn proof_by_email(
    State(state): State<AppState>,
    Path(email): Path<String>,
    Query(q): Query<ProofQuery>,
) -> AppResult<Json<ProofResponse>> {
    let email = openpgp::normalize_email(&email).ok_or(AppError::NotFound)?;
    let hash = kt::email_hash(&email);
    let resp = state
        .db()
        .call(move |c| -> AppResult<ProofResponse> {
            let latest = kt::latest_sth(c)?;
            let sth = match q.tree_size {
                None => latest,
                Some(n) if n <= latest.tree_size => kt::head(c, n)?
                    .ok_or_else(|| AppError::BadRequest(format!("no tree head of size {n}")))?,
                Some(n) => {
                    return Err(AppError::BadRequest(format!(
                        "tree_size {n} exceeds the log size {}",
                        latest.tree_size
                    )))
                }
            };
            let (leaf_index, entry, path) =
                kt::inclusion(c, &hash, sth.tree_size)?.ok_or(AppError::NotFound)?;
            let leaf_hash = hex::encode(kt::merkle::leaf_hash(entry.leaf_json().as_bytes()));
            Ok(ProofResponse {
                tree_size: sth.tree_size,
                leaf_index,
                entry,
                leaf_hash,
                audit_path: path.iter().map(hex::encode).collect(),
                sth,
            })
        })
        .await?;
    Ok(Json(resp))
}

/// `GET /v1/kt/consistency?from=&to=`
pub async fn consistency(
    State(state): State<AppState>,
    Query(q): Query<ConsistencyQuery>,
) -> AppResult<Json<ConsistencyResponse>> {
    let resp = state
        .db()
        .call(move |c| -> AppResult<ConsistencyResponse> {
            let size = kt::latest_sth(c)?.tree_size;
            let to = q.to.unwrap_or(size);
            if q.from > to || to > size {
                return Err(AppError::BadRequest(format!(
                    "need 0 <= from <= to <= {size} (got from={} to={to})",
                    q.from
                )));
            }
            let proof = kt::consistency(c, q.from, to)?;
            Ok(ConsistencyResponse {
                from: q.from,
                to,
                proof: proof.iter().map(hex::encode).collect(),
            })
        })
        .await?;
    Ok(Json(resp))
}

/// `GET /v1/kt/entries?start=&limit=`
pub async fn entries(
    State(state): State<AppState>,
    Query(q): Query<EntriesQuery>,
) -> AppResult<Json<EntriesResponse>> {
    let start = q.start.unwrap_or(0);
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let resp = state
        .db()
        .call(move |c| -> AppResult<EntriesResponse> {
            let tree_size = kt::latest_sth(c)?.tree_size;
            let entries = kt::entries(c, start, limit)?
                .into_iter()
                .map(|(index, entry, h)| IndexedEntry {
                    index,
                    entry,
                    leaf_hash: hex::encode(h),
                })
                .collect();
            Ok(EntriesResponse {
                tree_size,
                start,
                entries,
            })
        })
        .await?;
    Ok(Json(resp))
}
