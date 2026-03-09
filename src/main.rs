use anyhow::Result;
use dashmap::DashMap;
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Deserialize)]
struct Config {
    listen: String,
    upstream: String,
    policy_file: String,
    timeout_ms: u64,
}

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expiry: Instant,
}

#[derive(Clone)]
struct Policy {
    exact: HashSet<String>,
    wildcard: Vec<String>,
}

impl Policy {
    fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;

        let mut exact = HashSet::new();
        let mut wildcard = Vec::new();

        for line in content.lines() {
            let d = line.trim().to_lowercase();

            if d.is_empty() {
                continue;
            }

            if d.starts_with("*.") {
                wildcard.push(d.trim_start_matches("*.").to_string());
            } else {
                exact.insert(d);
            }
        }

        Ok(Self { exact, wildcard })
    }

    fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();

        if self.exact.contains(&domain) {
            return true;
        }

        for blocked in &self.exact {
            if domain.ends_with(&format!(".{}", blocked)) {
                return true;
            }
        }

        for w in &self.wildcard {
            if domain.ends_with(w) {
                return true;
            }
        }

        false
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config: Config = serde_json::from_str(&fs::read_to_string("config.json")?)?;

    let socket = Arc::new(UdpSocket::bind(&config.listen).await?);

    println!("DNS firewall running on {}", config.listen);

    let policy = Arc::new(Policy::load(&config.policy_file)?);

    let cache: Arc<DashMap<String, CacheEntry>> = Arc::new(DashMap::new());

    loop {
        let mut buf = [0u8; 512];

        let (size, src) = socket.recv_from(&mut buf).await?;

        let data = buf[..size].to_vec();

        let socket = socket.clone();
        let policy = policy.clone();
        let cache = cache.clone();
        let upstream = config.upstream.clone();
        let timeout_ms = config.timeout_ms;

        tokio::spawn(async move {
            if let Err(e) =
                handle_query(socket, src, data, policy, cache, upstream, timeout_ms).await
            {
                eprintln!("error: {:?}", e);
            }
        });
    }
}

async fn handle_query(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    packet: Vec<u8>,
    policy: Arc<Policy>,
    cache: Arc<DashMap<String, CacheEntry>>,
    upstream: String,
    timeout_ms: u64,
) -> Result<()> {
    let message = match Message::from_vec(&packet) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    let query = match message.queries().first() {
        Some(q) => q,
        None => return Ok(()),
    };

    let mut domain = query.name().to_ascii();

    if domain.ends_with('.') {
        domain.pop();
    }

    println!("Query {}", domain);

    if policy.is_blocked(&domain) {
        println!("Blocked {}", domain);

        let mut resp = Message::new();

        resp.set_id(message.id());
        resp.set_message_type(MessageType::Response);
        resp.set_response_code(ResponseCode::NXDomain);
        resp.add_query(query.clone());

        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);

        resp.emit(&mut encoder)?;

        socket.send_to(&bytes, src).await?;

        return Ok(());
    }

    if let Some(entry) = cache.get(&domain) {
        if Instant::now() < entry.expiry {
            socket.send_to(&entry.response, src).await?;
            return Ok(());
        }
    }

    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;

    upstream_socket.send_to(&packet, &upstream).await?;

    let mut upstream_buf = [0u8; 512];

    let result = timeout(
        Duration::from_millis(timeout_ms),
        upstream_socket.recv_from(&mut upstream_buf),
    )
    .await;

    let (size, _) = match result {
        Ok(r) => r?,
        Err(_) => {
            println!("upstream timeout");
            return Ok(());
        }
    };

    let response = upstream_buf[..size].to_vec();

    cache.insert(
        domain,
        CacheEntry {
            response: response.clone(),
            expiry: Instant::now() + Duration::from_secs(60),
        },
    );

    socket.send_to(&response, src).await?;

    Ok(())
}
