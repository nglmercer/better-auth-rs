//! In-process load test for the auth router.
//!
//! Drives `AuthRouter::handle` directly from concurrent tasks, so the numbers
//! describe the router, its password hashing and its storage. They do not include
//! HTTP parsing, a network hop or a database server. Run with:
//!
//! `cargo run --release -p better-auth --example load_test -- [concurrency] [requests]`

use better_auth::context::AuthContext;
use better_auth::router::{AuthRouter, HttpRequest};
use better_auth_core::{
    adapter::memory::{MemoryDb, MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

const PASSWORD: &str = "correct horse battery staple";

struct Sample {
    latency: Duration,
    status: StatusCode,
}

fn origin_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    headers
}

async fn run(
    router: Arc<AuthRouter>,
    concurrency: usize,
    total: usize,
    make: impl Fn() -> HttpRequest + Send + Sync + Clone + 'static,
) -> (Vec<Sample>, Duration) {
    let started = Instant::now();
    let per_task = total / concurrency;
    let mut tasks = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let router = Arc::clone(&router);
        let make = make.clone();
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::with_capacity(per_task);
            for _ in 0..per_task {
                let request = make();
                let begin = Instant::now();
                let response = router.handle(request).await;
                samples.push(Sample {
                    latency: begin.elapsed(),
                    status: response.status,
                });
            }
            samples
        }));
    }
    let mut all = Vec::with_capacity(total);
    for task in tasks {
        all.extend(task.await.expect("load task panicked"));
    }
    (all, started.elapsed())
}

fn report(name: &str, samples: &mut [Sample], wall: Duration, expected: &[StatusCode]) {
    samples.sort_by_key(|sample| sample.latency);
    let percentile = |p: f64| {
        let index = ((samples.len() as f64 - 1.0) * p).round() as usize;
        samples[index].latency
    };
    let unexpected = samples
        .iter()
        .filter(|s| !expected.contains(&s.status))
        .count();
    println!(
        "{name:<22} n={:<6} p50={:>8.2?} p95={:>8.2?} p99={:>8.2?} max={:>8.2?} throughput={:>8.1}/s unexpected={}",
        samples.len(),
        percentile(0.50),
        percentile(0.95),
        percentile(0.99),
        samples.last().map(|s| s.latency).unwrap_or_default(),
        samples.len() as f64 / wall.as_secs_f64(),
        unexpected,
    );
}

#[tokio::main]
async fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let concurrency = args.first().copied().unwrap_or(8).max(1);
    let total = args.get(1).copied().unwrap_or(400).max(concurrency);

    let context = AuthContext::new(
        AuthOptions {
            secret: "load-test-secret-0123456789abcdefghij".into(),
            base_url: Some(BaseUrl::Static("https://example.com".into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )
    .expect("valid configuration");
    let router = Arc::new(AuthRouter::new(context).expect("router"));

    let signup = router
        .handle(HttpRequest::new(
            Method::POST,
            "/api/auth/sign-up/email".parse().unwrap(),
            origin_headers(),
            json!({"email":"load@example.com","name":"Load","password":PASSWORD})
                .to_string()
                .into_bytes(),
        ))
        .await;
    let cookie = signup
        .headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .expect("sign-up sets a session cookie")
        .to_owned();

    println!("concurrency={concurrency} requests={total}");
    let session_cookie = cookie.clone();
    let (mut session, wall) = run(Arc::clone(&router), concurrency, total, move || {
        let mut headers = origin_headers();
        headers.insert(header::COOKIE, session_cookie.parse().unwrap());
        HttpRequest::new(
            Method::GET,
            "/api/auth/get-session".parse().unwrap(),
            headers,
            Vec::new(),
        )
    })
    .await;
    report("get-session", &mut session, wall, &[StatusCode::OK]);

    let (mut sign_in, wall) = run(Arc::clone(&router), concurrency, total, || {
        HttpRequest::new(
            Method::POST,
            "/api/auth/sign-in/email".parse().unwrap(),
            origin_headers(),
            json!({"email":"load@example.com","password":"wrong password here"})
                .to_string()
                .into_bytes(),
        )
    })
    .await;
    report(
        "sign-in (wrong pw)",
        &mut sign_in,
        wall,
        &[StatusCode::UNAUTHORIZED, StatusCode::TOO_MANY_REQUESTS],
    );
}
