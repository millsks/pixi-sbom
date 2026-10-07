//! A local HTTP server for the network tests (#318).
//!
//! The unit tests stub `Fetch` and never speak HTTP, and the CLI tests run offline, so anything
//! that only shows in how requests go over the wire fell between them: connection reuse, requests
//! that should overlap, retries, the cache counters. This server answers a script on
//! `127.0.0.1` and records what it saw, so those become assertions instead of stopwatch readings.
//!
//! It is deliberately small: HTTP/1.1 with keep-alive, `Content-Length` or chunked request bodies,
//! and `Content-Length` responses. No dependency, because the thing under test is the shape of the
//! traffic, which a client-side mock cannot see.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One request as the server saw it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: String,
    /// Which TCP connection carried it, numbered from 0 in the order they were accepted.
    pub connection: usize,
    pub started: Instant,
    pub finished: Instant,
}

impl Request {
    /// The request body as JSON, or `Null` when it is not JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// What to answer, and how long to take over it.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: String,
    pub delay: Duration,
}

impl Response {
    pub fn json(body: serde_json::Value) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }

    pub fn status(status: u16) -> Self {
        Self {
            status,
            body: String::new(),
            delay: Duration::ZERO,
        }
    }

    pub fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// The script: given the request and how many requests for the same path came before it, what
/// to answer.
type Script = dyn Fn(&Request, usize) -> Response + Send + Sync;

struct State {
    script: Box<Script>,
    connections: AtomicUsize,
    requests: Mutex<Vec<Request>>,
}

/// A server running on an ephemeral port until the test process ends.
pub struct Server {
    url: String,
    state: Arc<State>,
}

impl Server {
    pub fn start(script: impl Fn(&Request, usize) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(State {
            script: Box::new(script),
            connections: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        });
        let accepting = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let connection = accepting.connections.fetch_add(1, Ordering::SeqCst);
                let state = Arc::clone(&accepting);
                std::thread::spawn(move || serve(stream, connection, &state));
            }
        });
        Self { url, state }
    }

    /// `http://127.0.0.1:<port>`, without a trailing slash.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// Every request answered so far, in the order they finished.
    pub fn requests(&self) -> Vec<Request> {
        self.state.requests.lock().unwrap().clone()
    }

    /// The most requests matching `filter` that were being answered at the same moment.
    pub fn peak_overlap(&self, filter: impl Fn(&Request) -> bool) -> usize {
        let requests: Vec<Request> = self.requests().into_iter().filter(|r| filter(r)).collect();
        requests
            .iter()
            .map(|r| {
                requests
                    .iter()
                    .filter(|other| other.started <= r.started && r.started < other.finished)
                    .count()
            })
            .max()
            .unwrap_or(0)
    }
}

/// Answer requests on one connection until the client closes it.
fn serve(stream: TcpStream, connection: usize, state: &State) {
    let mut writer = stream.try_clone().expect("clone the stream");
    let mut reader = BufReader::new(stream);
    loop {
        let Some((method, path, body)) = read_request(&mut reader) else {
            return;
        };
        let started = Instant::now();
        let mut request = Request {
            method,
            path,
            body,
            connection,
            started,
            finished: started,
        };
        let earlier = state
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == request.path)
            .count();
        let response = (state.script)(&request, earlier);
        std::thread::sleep(response.delay);
        let head = format!(
            "HTTP/1.1 {} Scripted\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            response.status,
            response.body.len()
        );
        request.finished = Instant::now();
        // Recorded before the bytes go out, so a test that reads the log after the client has its
        // answer always finds the request in it.
        state.requests.lock().unwrap().push(request);
        if writer.write_all(head.as_bytes()).is_err() || writer.write_all(response.body.as_bytes()).is_err() {
            return;
        }
        let _ = writer.flush();
    }
}

/// Read one request: the request line, the headers, and a body by `Content-Length` or chunked.
/// `None` when the connection closed or sent something that is not HTTP.
fn read_request(reader: &mut BufReader<TcpStream>) -> Option<(String, String, String)> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut length = 0usize;
    let mut chunked = false;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            return None;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().ok()?,
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            _ => {}
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).ok()?;
            let size = usize::from_str_radix(size.trim().split(';').next()?, 16).ok()?;
            let mut chunk = vec![0; size + 2];
            reader.read_exact(&mut chunk).ok()?;
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        body.resize(length, 0);
        reader.read_exact(&mut body).ok()?;
    }
    Some((method, path, String::from_utf8_lossy(&body).into_owned()))
}
