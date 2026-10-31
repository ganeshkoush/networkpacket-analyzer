mod backend;

use std::path::PathBuf;
use std::time::Duration;

use backend::{Backend, BackendInfo, Launch, Phase};
use tauri::{Manager, RunEvent, State};

/// Installed (release) builds must carry the packaged backend and start it. Development builds (`npm run tauri dev`) do not:
/// the developer runs the backend themselves on port 8765, exactly as before, and the frontend keeps its default address.
const BACKEND_DIR_IN_RESOURCES: &str = "backend";
const BACKEND_EXE: &str = "packetmind-backend";

struct Managed {
    backend: Option<Backend>,
    /// Why the packaged backend could not even be launched (release builds only). Shown on the startup screen.
    setup_error: Option<String>,
}

fn startup_timeout() -> Duration {
    // Generous by default: the first launch of a newly installed app can take a while (macOS scans new binaries).
    let secs = std::env::var("PACKETMIND_STARTUP_TIMEOUT_SECS").ok().and_then(|v| v.parse::<u64>().ok()).filter(|s| (1..=600).contains(s)).unwrap_or(60);
    Duration::from_secs(secs)
}

fn build_backend(app: &tauri::App) -> Result<Option<Backend>, String> {
    let resources = app.path().resource_dir().map_err(|e| format!("Cannot locate the app resources: {e}"))?;
    let exe: PathBuf = resources.join(BACKEND_DIR_IN_RESOURCES).join(BACKEND_EXE);
    if !exe.is_file() {
        if cfg!(debug_assertions) {
            return Ok(None); // development: external backend
        }
        return Err(format!("The backend component is missing from this installation ({}). Reinstall PacketMind.", exe.display()));
    }
    // Everything PacketMind writes (database, captures, reports, backend logs) lives in the user's Application Support
    // folder - never inside the read-only app bundle, and it survives app upgrades.
    let data = app.path().app_data_dir().map_err(|e| format!("Cannot locate the application data folder: {e}"))?;
    let logs = app.path().app_log_dir().map_err(|e| format!("Cannot locate the log folder: {e}"))?;
    let port = backend::free_port().map_err(|e| format!("No free local port is available: {e}"))?;
    let token = backend::new_token().map_err(|e| format!("Cannot create the access token: {e}"))?;

    let mut env = vec![
        ("PACKETMIND_DATA_DIR".to_string(), data.to_string_lossy().into_owned()),
        ("PACKETMIND_HOST".to_string(), "127.0.0.1".to_string()),
        ("PACKETMIND_PORT".to_string(), port.to_string()),
        ("PACKETMIND_API_TOKEN".to_string(), token.clone()),
        ("PACKETMIND_PARENT_PID".to_string(), std::process::id().to_string()),
    ];
    // The one-time capture-permission script ships inside the app; the backend names it in its permission hint.
    let script = resources.join("scripts").join("macos-bpf-access.sh");
    if script.is_file() {
        env.push(("PACKETMIND_BPF_SCRIPT".to_string(), script.to_string_lossy().into_owned()));
    }
    let launch = Launch {
        program: exe,
        args: vec![],
        env,
        workdir: data,
        log_file: logs.join("backend.log"),
        port,
        startup_timeout: startup_timeout(),
        max_restarts: 3,
    };
    Ok(Some(Backend::new(launch, token)))
}

/// Called by the frontend before its first request. `Ok(None)` = development build, use the default address.
/// Blocks (off the UI thread) until the backend answers its readiness check, or reports why it could not start.
#[tauri::command]
async fn backend_info(state: State<'_, Managed>) -> Result<Option<BackendInfo>, String> {
    if let Some(m) = &state.setup_error {
        return Err(m.clone());
    }
    let Some(b) = state.backend.clone() else { return Ok(None) };
    let limit = startup_timeout() + Duration::from_secs(5);
    let phase = tauri::async_runtime::spawn_blocking(move || b.wait_settled(limit)).await.map_err(|e| e.to_string())?;
    match phase {
        Phase::Ready(info) => Ok(Some(info)),
        Phase::Failed(m) => Err(m),
        Phase::Starting => Err("The PacketMind backend is still starting. Try again in a moment.".into()),
    }
}

/// "Try again" on the startup error screen. Safe to call repeatedly: at most one backend process ever runs.
#[tauri::command]
fn retry_backend(state: State<'_, Managed>) {
    if let Some(b) = &state.backend {
        b.start();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        // Native open/save dialogs: the user picks where a capture is exported; the backend validates and writes it.
        .plugin(tauri_plugin_dialog::init())
        // Desktop notifications (Settings → Notifications decides which events use them).
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![backend_info, retry_backend])
        .setup(|app| {
            match build_backend(app) {
                Ok(b) => {
                    if let Some(b) = &b {
                        b.start();
                    }
                    app.manage(Managed { backend: b, setup_error: None });
                }
                Err(message) => {
                    // Surfaced on the frontend's startup screen via backend_info; nothing is started.
                    eprintln!("PacketMind backend setup failed: {message}");
                    app.manage(Managed { backend: None, setup_error: Some(message) });
                }
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building PacketMind");

    // Closing the last window quits PacketMind (and with it the backend): a deliberate policy, so no hidden background
    // backend or capture keeps running after the window is gone.
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(m) = handle.try_state::<Managed>() {
                if let Some(b) = &m.backend {
                    b.shutdown();
                }
            }
        }
    });
}
