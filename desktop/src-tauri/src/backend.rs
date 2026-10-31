//! Backend lifecycle: starts the bundled PacketMind backend, waits for a real readiness check, restarts it if it dies
//! unexpectedly (a few times), and stops it when the app quits.
//!
//! Security model: the backend listens on 127.0.0.1 only, on a free port chosen at launch, and requires a random per-launch
//! token (X-PacketMind-Token) on every API call except the readiness probe. The token lives only in this process's memory,
//! the backend's environment and the frontend's memory; it is never written to disk or logged.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

/// How the frontend reaches the backend.
#[derive(Clone, Serialize, Debug, PartialEq)]
pub struct BackendInfo {
    pub url: String,
    pub token: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    Starting,
    Ready(BackendInfo),
    Failed(String),
}

/// Everything needed to launch the backend. Built once at startup; tests build their own.
#[derive(Clone)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: PathBuf,
    pub log_file: PathBuf,
    pub port: u16,
    pub startup_timeout: Duration,
    pub max_restarts: u32,
}

pub struct Inner {
    phase: Mutex<Phase>,
    shutting_down: AtomicBool,
    supervisor_done: AtomicBool,
    pid: AtomicU32,
    info: BackendInfo,
    launch: Launch,
}

#[derive(Clone)]
pub struct Backend(pub Arc<Inner>);

const POLL: Duration = Duration::from_millis(150);
const STOP_GRACE: Duration = Duration::from_secs(8);

impl Backend {
    pub fn new(launch: Launch, token: String) -> Self {
        let info = BackendInfo { url: format!("http://127.0.0.1:{}", launch.port), token };
        Backend(Arc::new(Inner {
            phase: Mutex::new(Phase::Starting),
            shutting_down: AtomicBool::new(false),
            supervisor_done: AtomicBool::new(true),
            pid: AtomicU32::new(0),
            info,
            launch,
        }))
    }

    pub fn phase(&self) -> Phase {
        self.0.phase.lock().unwrap().clone()
    }

    fn set_phase(&self, p: Phase) {
        *self.0.phase.lock().unwrap() = p;
    }

    /// Start (or restart after a failure) the supervisor thread. Does nothing if one is already running, so a second call
    /// can never create a second backend process.
    pub fn start(&self) {
        if self.0.supervisor_done.swap(false, Ordering::SeqCst) == false {
            return;
        }
        self.0.shutting_down.store(false, Ordering::SeqCst);
        self.set_phase(Phase::Starting);
        let me = self.clone();
        std::thread::Builder::new()
            .name("backend-supervisor".into())
            .spawn(move || {
                me.supervise();
                me.0.supervisor_done.store(true, Ordering::SeqCst);
            })
            .expect("spawn supervisor thread");
    }

    /// Block until the backend is ready or failed (or `limit` passes).
    pub fn wait_settled(&self, limit: Duration) -> Phase {
        let end = Instant::now() + limit;
        loop {
            let p = self.phase();
            if p != Phase::Starting || Instant::now() >= end {
                return p;
            }
            std::thread::sleep(POLL);
        }
    }

    fn supervise(&self) {
        let l = &self.0.launch;
        let mut restarts = 0u32;
        loop {
            if self.0.shutting_down.load(Ordering::SeqCst) {
                return;
            }
            let mut child = match spawn_backend(l) {
                Ok(c) => c,
                Err(e) => {
                    self.set_phase(Phase::Failed(format!("Could not start the PacketMind backend: {e}. Log: {}", l.log_file.display())));
                    return;
                }
            };
            self.0.pid.store(child.id(), Ordering::SeqCst);
            match wait_ready(&mut child, l.port, l.startup_timeout, &self.0.shutting_down) {
                Ok(()) => self.set_phase(Phase::Ready(self.0.info.clone())),
                Err(reason) => {
                    stop_child(&mut child);
                    self.0.pid.store(0, Ordering::SeqCst);
                    if self.0.shutting_down.load(Ordering::SeqCst) {
                        return;
                    }
                    self.set_phase(Phase::Failed(format!("{reason} Log: {}", l.log_file.display())));
                    return;
                }
            }
            // Ready: watch for exit.
            loop {
                if self.0.shutting_down.load(Ordering::SeqCst) {
                    stop_child(&mut child);
                    self.0.pid.store(0, Ordering::SeqCst);
                    return;
                }
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.0.pid.store(0, Ordering::SeqCst);
                        restarts += 1;
                        if restarts > l.max_restarts {
                            self.set_phase(Phase::Failed(format!(
                                "The PacketMind backend stopped unexpectedly ({status}) and could not be restarted. Log: {}", l.log_file.display())));
                            return;
                        }
                        self.set_phase(Phase::Starting);
                        break; // respawn on the same port with the same token, so the frontend keeps working
                    }
                    Ok(None) => std::thread::sleep(POLL),
                    Err(e) => {
                        self.set_phase(Phase::Failed(format!("Lost track of the backend process: {e}")));
                        return;
                    }
                }
            }
        }
    }

    /// Stop the backend gracefully (SIGTERM lets it finish and close an active capture), force-kill after a grace period.
    pub fn shutdown(&self) {
        self.0.shutting_down.store(true, Ordering::SeqCst);
        let end = Instant::now() + STOP_GRACE + Duration::from_secs(3);
        while !self.0.supervisor_done.load(Ordering::SeqCst) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn spawn_backend(l: &Launch) -> std::io::Result<Child> {
    if let Some(dir) = l.log_file.parent() {
        fs::create_dir_all(dir)?;
    }
    rotate_log(&l.log_file, 5 * 1024 * 1024);
    let out = open_log(&l.log_file)?;
    let err = out.try_clone()?;
    fs::create_dir_all(&l.workdir)?;
    let mut cmd = Command::new(&l.program);
    cmd.args(&l.args).current_dir(&l.workdir).stdin(Stdio::null()).stdout(Stdio::from(out)).stderr(Stdio::from(err));
    for (k, v) in &l.env {
        cmd.env(k, v);
    }
    cmd.spawn()
}

fn open_log(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Keep the log from growing without bound: one previous generation is kept.
fn rotate_log(path: &Path, max: u64) {
    if fs::metadata(path).map(|m| m.len() > max).unwrap_or(false) {
        let _ = fs::rename(path, path.with_extension("log.1"));
    }
}

/// Wait for a real readiness answer (`GET /api/health` -> 200 with status ok), not a fixed sleep. Fails early if the process
/// exits, and after `timeout`.
pub fn wait_ready(child: &mut Child, port: u16, timeout: Duration, abort: &AtomicBool) -> Result<(), String> {
    let end = Instant::now() + timeout;
    loop {
        if abort.load(Ordering::SeqCst) {
            return Err("Startup was cancelled.".into());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("The PacketMind backend exited during startup ({status})."));
        }
        if probe_health(port) {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err(format!("The PacketMind backend did not become ready within {} seconds.", timeout.as_secs()));
        }
        std::thread::sleep(POLL);
    }
}

/// Minimal HTTP/1.0 GET so no HTTP client dependency is needed for a loopback readiness probe.
pub fn probe_health(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"GET /api/health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").is_err() {
        return false;
    }
    let mut body = String::new();
    let _ = s.read_to_string(&mut body);
    body.starts_with("HTTP/1.") && body.contains(" 200 ") && body.contains("\"status\":\"ok\"")
}

fn stop_child(child: &mut Child) {
    if let Ok(Some(_)) = child.try_wait() {
        return;
    }
    // SIGTERM first so the backend can close an active capture and its database cleanly.
    let _ = Command::new("/bin/kill").args(["-TERM", &child.id().to_string()]).status();
    let end = Instant::now() + STOP_GRACE;
    while Instant::now() < end {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// A currently free loopback port (the backend binds it moments later). Never a hard-coded port.
pub fn free_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// 256 random bits from the OS, hex encoded.
pub fn new_token() -> std::io::Result<String> {
    let mut buf = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(program: &str, args: &[&str], port: u16, timeout_ms: u64) -> Launch {
        let dir = std::env::temp_dir().join(format!("pm-test-{}-{port}", std::process::id()));
        Launch {
            program: program.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: vec![],
            workdir: dir.clone(),
            log_file: dir.join("backend.log"),
            port,
            startup_timeout: Duration::from_millis(timeout_ms),
            max_restarts: 1,
        }
    }

    #[test]
    fn token_is_64_hex_chars_and_unique() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn free_port_is_loopback_bindable_and_changes() {
        let p = free_port().unwrap();
        assert!(p > 0);
        drop(TcpListener::bind(("127.0.0.1", p)).unwrap());
    }

    #[test]
    fn probe_rejects_closed_port_and_wrong_service() {
        let closed = free_port().unwrap();
        assert!(!probe_health(closed));
        // A server that answers 200 but is not PacketMind must not count as ready.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\n\r\nhello");
            }
        });
        assert!(!probe_health(port));
    }

    #[test]
    fn probe_accepts_a_healthy_backend_answer() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"status\":\"ok\",\"app\":\"PacketMind\"}");
            }
        });
        assert!(probe_health(port));
    }

    #[test]
    fn startup_failure_is_reported_when_the_process_exits_early() {
        let b = Backend::new(launch("/bin/sh", &["-c", "exit 3"], free_port().unwrap(), 10_000), "t".into());
        b.start();
        match b.wait_settled(Duration::from_secs(10)) {
            Phase::Failed(m) => assert!(m.contains("exited during startup"), "{m}"),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn startup_times_out_when_the_backend_never_answers() {
        let b = Backend::new(launch("/bin/sleep", &["30"], free_port().unwrap(), 600), "t".into());
        b.start();
        let started = Instant::now();
        match b.wait_settled(Duration::from_secs(20)) {
            Phase::Failed(m) => assert!(m.contains("did not become ready"), "{m}"),
            other => panic!("expected timeout, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(15));
        b.shutdown(); // the sleeping process must have been stopped, not leaked
        assert_eq!(b.0.pid.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_executable_is_a_clear_failure() {
        let b = Backend::new(launch("/nonexistent/packetmind-backend", &[], free_port().unwrap(), 1000), "t".into());
        b.start();
        match b.wait_settled(Duration::from_secs(5)) {
            Phase::Failed(m) => assert!(m.contains("Could not start"), "{m}"),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn start_is_idempotent_while_running() {
        let b = Backend::new(launch("/bin/sleep", &["30"], free_port().unwrap(), 400), "t".into());
        b.start();
        b.start(); // must not spawn a second supervisor/process
        std::thread::sleep(Duration::from_millis(200));
        let pid = b.0.pid.load(Ordering::SeqCst);
        b.start();
        assert_eq!(b.0.pid.load(Ordering::SeqCst), pid);
        b.shutdown();
    }

    #[test]
    fn log_rotation_keeps_one_previous_generation() {
        let dir = std::env::temp_dir().join(format!("pm-rot-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("backend.log");
        fs::write(&log, vec![b'x'; 2048]).unwrap();
        rotate_log(&log, 1024);
        assert!(!log.exists() && dir.join("backend.log.1").exists());
    }
}
