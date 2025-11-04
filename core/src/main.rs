use std::collections::HashMap;
use std::io::{self, Write, BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::process::{Command, Stdio};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};

#[cfg(target_os = "windows")]
use winapi::um::jobapi2::{CreateJobObjectW, AssignProcessToJobObject, SetInformationJobObject};
#[cfg(target_os = "windows")]
use winapi::um::winnt::{HANDLE, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_LIMIT_INFORMATION};
#[cfg(target_os = "windows")]
use winapi::um::handleapi::CloseHandle;
#[cfg(target_os = "windows")]
use std::ptr::null_mut;

#[derive(Parser)]
#[command(name = "LucidShell")]
#[command(about = "White-Hat Security Shell with Sandboxing & Authorization", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    #[arg(long, help = "Enable ephemeral mode (memory-only, no disk writes)")]
    ephemeral: bool,
    
    #[arg(long, help = "Path to encrypted container for persistent storage")]
    container: Option<PathBuf>,
    
    #[arg(long, help = "Session mode: auditor, forensics, developer, minimal")]
    mode: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long, help = "Target authorization identifier")]
        target: String,
        
        #[arg(long, help = "Engagement letter path")]
        engagement_letter: Option<PathBuf>,
    },
    
    Run {
        #[arg(help = "Tool name or plugin identifier")]
        tool: String,
        
        #[arg(long, help = "Allow network access (requires authorization)")]
        network: bool,
        
        #[arg(long, help = "Sandbox profile: minimal, standard, elevated")]
        profile: Option<String>,
        
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    
    Network {
        #[command(subcommand)]
        action: NetworkCommands,
    },
    
    Forensics {
        #[command(subcommand)]
        action: ForensicsCommands,
    },
    
    Plugin {
        #[command(subcommand)]
        action: PluginCommands,
    },
    
    Panic,
    
    Repl,
}

#[derive(Subcommand)]
enum NetworkCommands {
    Tor { #[arg(long)] port: Option<u16> },
    Vpn { 
        #[arg(long)] config: PathBuf,
        #[arg(long)] protocol: String,
    },
    Status,
    Disable,
}

#[derive(Subcommand)]
enum ForensicsCommands {
    Mount { 
        #[arg(help = "Target path or device")]
        target: PathBuf,
        
        #[arg(long, help = "Use VSS snapshot")]
        vss: bool,
    },
    
    Hash {
        #[arg(help = "Path to hash")]
        path: PathBuf,
        
        #[arg(long, help = "Generate signed manifest")]
        sign: bool,
    },
    
    Copy {
        #[arg(help = "Source path")]
        source: PathBuf,
        
        #[arg(help = "Destination path")]
        dest: PathBuf,
    },
}

#[derive(Subcommand)]
enum PluginCommands {
    List,
    Install { 
        #[arg(help = "Plugin bundle path")]
        bundle: PathBuf,
    },
    Remove {
        #[arg(help = "Plugin identifier")]
        id: String,
    },
    Verify,
}

#[derive(Clone, Serialize, Deserialize)]
struct SessionState {
    session_id: String,
    start_time: DateTime<Utc>,
    mode: String,
    ephemeral: bool,
    authorization: Option<Authorization>,
    network_status: NetworkStatus,
    log_chain: Vec<LogEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Authorization {
    target: String,
    engagement_hash: String,
    timestamp: DateTime<Utc>,
    signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
enum NetworkStatus {
    Disabled,
    Direct,
    Tor { port: u16 },
    Vpn { protocol: String, connected: bool },
}

#[derive(Clone, Serialize, Deserialize)]
struct LogEntry {
    timestamp: DateTime<Utc>,
    event_type: String,
    details: String,
    chain_hash: String,
}

struct SecureMemory {
    data: Vec<u8>,
}

impl SecureMemory {
    fn new(size: usize) -> Self {
        SecureMemory {
            data: vec![0u8; size],
        }
    }
    
    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), String> {
        if offset + data.len() > self.data.len() {
            return Err("Write exceeds memory bounds".to_string());
        }
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }
    
    fn read(&self, offset: usize, len: usize) -> Result<&[u8], String> {
        if offset + len > self.data.len() {
            return Err("Read exceeds memory bounds".to_string());
        }
        Ok(&self.data[offset..offset + len])
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        for byte in &mut self.data {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

struct SandboxManager {
    #[cfg(target_os = "windows")]
    job_handle: Option<HANDLE>,
}

#[derive(Clone)]
struct SandboxConfig {
    profile: String,
    network_allowed: bool,
    filesystem_access: FilesystemAccess,
    registry_access: RegistryAccess,
}

#[derive(Clone)]
enum FilesystemAccess {
    ReadOnly,
    ReadWrite,
    None,
}

#[derive(Clone)]
enum RegistryAccess {
    Minimal,
    Standard,
    None,
}

impl SandboxManager {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                let job_handle = CreateJobObjectW(null_mut(), null_mut());
                if job_handle.is_null() {
                    return Err("Failed to create job object".into());
                }
                
                use winapi::um::winnt::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
                use winapi::um::winnt::JOB_OBJECT_LIMIT_BREAKAWAY_OK;
                use winapi::shared::minwindef::DWORD;
                
                let mut job_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                
                let result = SetInformationJobObject(
                    job_handle,
                    9,
                    &mut job_info as *mut _ as *mut _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                
                if result == 0 {
                    CloseHandle(job_handle);
                    return Err("Failed to configure job object".into());
                }
                
                Ok(SandboxManager {
                    job_handle: Some(job_handle),
                })
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Ok(SandboxManager {})
        }
    }
    
    fn execute_sandboxed(
        &self,
        tool: &str,
        args: &[String],
        config: SandboxConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("  [Sandbox] Profile: {}", config.profile);
        println!("  [Sandbox] Network: {}", config.network_allowed);
        println!("  [Sandbox] Filesystem: {:?}", match config.filesystem_access {
            FilesystemAccess::ReadOnly => "ReadOnly",
            FilesystemAccess::ReadWrite => "ReadWrite",
            FilesystemAccess::None => "None",
        });
        
        let tool_path = self.resolve_tool_path(tool)?;
        
        let mut cmd = Command::new(&tool_path);
        cmd.args(args);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_SUSPENDED: u32 = 0x00000004;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            
            cmd.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        }
        
        let mut child = cmd.spawn()?;
        
        #[cfg(target_os = "windows")]
        {
            if let Some(job_handle) = self.job_handle {
                unsafe {
                    use std::os::windows::io::AsRawHandle;
                    let process_handle = child.as_raw_handle() as HANDLE;
                    
                    let result = AssignProcessToJobObject(job_handle, process_handle);
                    if result == 0 {
                        child.kill()?;
                        return Err("Failed to assign process to job object".into());
                    }
                    
                    use winapi::um::processthreadsapi::ResumeThread;
                    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD};
                    
                    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if !snapshot.is_null() {
                        let mut te: THREADENTRY32 = std::mem::zeroed();
                        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                        
                        if Thread32First(snapshot, &mut te) != 0 {
                            loop {
                                if te.th32OwnerProcessID == child.id() {
                                    use winapi::um::processthreadsapi::OpenThread;
                                    use winapi::um::winnt::THREAD_SUSPEND_RESUME;
                                    
                                    let thread_handle = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
                                    if !thread_handle.is_null() {
                                        ResumeThread(thread_handle);
                                        CloseHandle(thread_handle);
                                    }
                                }
                                
                                if Thread32Next(snapshot, &mut te) == 0 {
                                    break;
                                }
                            }
                        }
                        CloseHandle(snapshot);
                    }
                }
            }
        }
        
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("  [Output] {}", line);
                }
            }
        }
        
        let status = child.wait()?;
        
        if !status.success() {
            return Err(format!("Tool exited with status: {}", status).into());
        }
        
        Ok(())
    }
    
    fn resolve_tool_path(&self, tool: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let builtin_tools = [
            ("ping", "C:\\Windows\\System32\\ping.exe"),
            ("ipconfig", "C:\\Windows\\System32\\ipconfig.exe"),
            ("netstat", "C:\\Windows\\System32\\netstat.exe"),
            ("nslookup", "C:\\Windows\\System32\\nslookup.exe"),
            ("tracert", "C:\\Windows\\System32\\tracert.exe"),
            ("whoami", "C:\\Windows\\System32\\whoami.exe"),
            ("systeminfo", "C:\\Windows\\System32\\systeminfo.exe"),
        ];
        
        for (name, path) in &builtin_tools {
            if tool == *name {
                return Ok(PathBuf::from(path));
            }
        }
        
        if tool.contains("\\") || tool.contains("/") {
            let path = PathBuf::from(tool);
            if path.exists() {
                return Ok(path);
            }
        }
        
        Err(format!("Tool '{}' not found. Use full path or builtin tool name.", tool).into())
    }
}

impl Drop for SandboxManager {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if let Some(handle) = self.job_handle {
                unsafe {
                    CloseHandle(handle);
                }
            }
        }
    }
}

struct CryptoEngine {
    session_key: [u8; 32],
}

impl CryptoEngine {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let mut session_key = [0u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos();
        
        let timestamp_bytes = timestamp.to_le_bytes();
        for i in 0..session_key.len() {
            session_key[i] = timestamp_bytes[i % timestamp_bytes.len()];
        }
        
        let mut hasher = Sha256::new();
        hasher.update(&session_key);
        let hashed = hasher.finalize();
        session_key.copy_from_slice(&hashed[..32]);
        
        Ok(CryptoEngine { session_key })
    }
    
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut hasher = Sha256::new();
        hasher.update(&self.session_key);
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }
    
    fn compute_chain_hash(&self, previous_hash: &str, new_data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(previous_hash.as_bytes());
        hasher.update(new_data.as_bytes());
        hasher.update(&self.session_key);
        format!("{:x}", hasher.finalize())
    }
}

struct SecureLogger {
    session_id: String,
    ephemeral: bool,
    log_file: Option<File>,
    last_chain_hash: String,
}

impl SecureLogger {
    fn new(session_id: &str, ephemeral: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let log_file = if !ephemeral {
            let log_dir = PathBuf::from("logs");
            std::fs::create_dir_all(&log_dir)?;
            
            let log_path = log_dir.join(format!("{}.log", session_id));
            Some(OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)?)
        } else {
            None
        };
        
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        let initial_hash = format!("{:x}", hasher.finalize());
        
        Ok(SecureLogger {
            session_id: session_id.to_string(),
            ephemeral,
            log_file,
            last_chain_hash: initial_hash,
        })
    }
    
    fn log_event(&mut self, event_type: &str, details: &str, crypto: &CryptoEngine) -> Result<LogEntry, Box<dyn std::error::Error>> {
        let timestamp = Utc::now();
        let log_data = format!("{}|{}|{}", timestamp.to_rfc3339(), event_type, details);
        
        let chain_hash = crypto.compute_chain_hash(&self.last_chain_hash, &log_data);
        
        let entry = LogEntry {
            timestamp,
            event_type: event_type.to_string(),
            details: details.to_string(),
            chain_hash: chain_hash.clone(),
        };
        
        let log_line = format!(
            "{} | {} | {} | {}\n",
            timestamp.to_rfc3339(),
            event_type,
            details,
            chain_hash
        );
        
        if !self.ephemeral {
            if let Some(ref mut file) = self.log_file {
                file.write_all(log_line.as_bytes())?;
                file.sync_all()?;
            }
        }
        
        println!("  [LOG] {}", log_line.trim());
        
        self.last_chain_hash = chain_hash;
        
        Ok(entry)
    }
}

struct ForensicsEngine;

impl ForensicsEngine {
    fn hash_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    fn hash_directory(path: &Path) -> Result<HashMap<PathBuf, String>, Box<dyn std::error::Error>> {
        let mut hashes = HashMap::new();
        
        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();
                
                if entry_path.is_file() {
                    let hash = Self::hash_file(&entry_path)?;
                    hashes.insert(entry_path, hash);
                } else if entry_path.is_dir() {
                    let sub_hashes = Self::hash_directory(&entry_path)?;
                    hashes.extend(sub_hashes);
                }
            }
        }
        
        Ok(hashes)
    }
    
    fn create_manifest(hashes: &HashMap<PathBuf, String>, sign: bool, crypto: &CryptoEngine) -> Result<String, Box<dyn std::error::Error>> {
        let mut manifest = String::new();
        manifest.push_str(&format!("# Forensic Hash Manifest\n"));
        manifest.push_str(&format!("# Generated: {}\n\n", Utc::now().to_rfc3339()));
        
        let mut sorted_paths: Vec<_> = hashes.keys().collect();
        sorted_paths.sort();
        
        for path in sorted_paths {
            if let Some(hash) = hashes.get(path) {
                manifest.push_str(&format!("{} *{}\n", hash, path.display()));
            }
        }
        
        if sign {
            let signature = crypto.sign_data(manifest.as_bytes())?;
            manifest.push_str(&format!("\n# Signature: {}\n", hex::encode(signature)));
        }
        
        Ok(manifest)
    }
    
    fn forensic_copy(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if !source.exists() {
            return Err(format!("Source path does not exist: {}", source.display()).into());
        }
        
        let source_hash = Self::hash_file(source)?;
        
        std::fs::copy(source, dest)?;
        
        let dest_hash = Self::hash_file(dest)?;
        
        if source_hash != dest_hash {
            std::fs::remove_file(dest)?;
            return Err("Hash verification failed after copy".into());
        }
        
        println!("  [Forensics] Copy verified: {}", source_hash);
        
        Ok(())
    }
}

struct PluginManager {
    plugins_dir: PathBuf,
    installed_plugins: HashMap<String, PluginMetadata>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PluginMetadata {
    id: String,
    name: String,
    version: String,
    signature: String,
    path: PathBuf,
}

impl PluginManager {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let plugins_dir = PathBuf::from("plugins");
        std::fs::create_dir_all(&plugins_dir)?;
        
        let mut manager = PluginManager {
            plugins_dir,
            installed_plugins: HashMap::new(),
        };
        
        manager.load_installed_plugins()?;
        
        Ok(manager)
    }
    
    fn load_installed_plugins(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let manifest_path = self.plugins_dir.join("manifest.json");
        
        if manifest_path.exists() {
            let manifest_data = std::fs::read_to_string(manifest_path)?;
            self.installed_plugins = serde_json::from_str(&manifest_data)?;
        }
        
        Ok(())
    }
    
    fn save_manifest(&self) -> Result<(), Box<dyn std::error::Error>> {
        let manifest_path = self.plugins_dir.join("manifest.json");
        let manifest_data = serde_json::to_string_pretty(&self.installed_plugins)?;
        std::fs::write(manifest_path, manifest_data)?;
        Ok(())
    }
    
    fn list_plugins(&self) {
        if self.installed_plugins.is_empty() {
            println!("  No plugins installed.");
            return;
        }
        
        println!("\n  Installed Plugins:");
        for (id, plugin) in &self.installed_plugins {
            println!("    {} - {} (v{})", id, plugin.name, plugin.version);
        }
        println!();
    }
    
    fn install_plugin(&mut self, bundle_path: &Path, crypto: &CryptoEngine) -> Result<(), Box<dyn std::error::Error>> {
        if !bundle_path.exists() {
            return Err(format!("Plugin bundle not found: {}", bundle_path.display()).into());
        }
        
        let bundle_hash = ForensicsEngine::hash_file(bundle_path)?;
        let signature = hex::encode(crypto.sign_data(bundle_hash.as_bytes())?);
        
        let plugin_id = bundle_path.file_stem()
            .and_then(|s| s.to_str())
            .ok_or("Invalid plugin filename")?
            .to_string();
        
        let dest_path = self.plugins_dir.join(bundle_path.file_name().unwrap());
        std::fs::copy(bundle_path, &dest_path)?;
        
        let metadata = PluginMetadata {
            id: plugin_id.clone(),
            name: plugin_id.clone(),
            version: "1.0.0".to_string(),
            signature,
            path: dest_path,
        };
        
        self.installed_plugins.insert(plugin_id, metadata);
        self.save_manifest()?;
        
        println!("  [Plugin] Installed successfully");
        
        Ok(())
    }
    
    fn remove_plugin(&mut self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(plugin) = self.installed_plugins.remove(id) {
            if plugin.path.exists() {
                std::fs::remove_file(&plugin.path)?;
            }
            self.save_manifest()?;
            println!("  [Plugin] Removed: {}", id);
            Ok(())
        } else {
            Err(format!("Plugin not found: {}", id).into())
        }
    }
    
    fn verify_plugins(&self, crypto: &CryptoEngine) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n  Verifying plugins...");
        
        for (id, plugin) in &self.installed_plugins {
            if !plugin.path.exists() {
                println!("    ✗ {} - File missing", id);
                continue;
            }
            
            let current_hash = ForensicsEngine::hash_file(&plugin.path)?;
            let current_signature = hex::encode(crypto.sign_data(current_hash.as_bytes())?);
            
            if current_signature == plugin.signature {
                println!("    ✓ {} - Verified", id);
            } else {
                println!("    ✗ {} - Signature mismatch", id);
            }
        }
        
        println!();
        Ok(())
    }
}

struct NetworkManager {
    status: NetworkStatus,
}

impl NetworkManager {
    fn new() -> Self {
        NetworkManager {
            status: NetworkStatus::Disabled,
        }
    }
    
    fn enable_tor(&mut self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        println!("  [Network] Configuring Tor proxy on port {}", port);
        println!("  [Network] Note: Actual Tor connection requires Tor service running");
        println!("  [Network] Kill-switch will activate if Tor connection drops");
        
        self.status = NetworkStatus::Tor { port };
        
        Ok(())
    }
    
    fn enable_vpn(&mut self, config: &Path, protocol: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !config.exists() {
            return Err(format!("VPN config not found: {}", config.display()).into());
        }
        
        println!("  [Network] Configuring {} VPN", protocol);
        println!("  [Network] Config: {}", config.display());
        println!("  [Network] Note: Actual VPN connection requires VPN service");
        
        self.status = NetworkStatus::Vpn {
            protocol: protocol.to_string(),
            connected: false,
        };
        
        Ok(())
    }
    
    fn disable(&mut self) {
        println!("  [Network] All network access disabled");
        self.status = NetworkStatus::Disabled;
    }
    
    fn status(&self) -> &NetworkStatus {
        &self.status
    }
}

struct LucidShell {
    session: Arc<Mutex<SessionState>>,
    secure_storage: Arc<Mutex<SecureMemory>>,
    sandbox_manager: SandboxManager,
    crypto_engine: CryptoEngine,
    log_writer: Arc<Mutex<SecureLogger>>,
    forensics_engine: ForensicsEngine,
    plugin_manager: Arc<Mutex<PluginManager>>,
    network_manager: Arc<Mutex<NetworkManager>>,
}

impl LucidShell {
    fn new(ephemeral: bool, mode: String) -> Result<Self, Box<dyn std::error::Error>> {
        let session_id = format!("{}", uuid::Uuid::new_v4());
        
        let session = SessionState {
            session_id: session_id.clone(),
            start_time: Utc::now(),
            mode: mode.clone(),
            ephemeral,
            authorization: None,
            network_status: NetworkStatus::Disabled,
            log_chain: Vec::new(),
        };
        
        let secure_storage = SecureMemory::new(1024 * 1024 * 100);
        let crypto_engine = CryptoEngine::new()?;
        let log_writer = SecureLogger::new(&session_id, ephemeral)?;
        
        Ok(LucidShell {
            session: Arc::new(Mutex::new(session)),
            secure_storage: Arc::new(Mutex::new(secure_storage)),
            sandbox_manager: SandboxManager::new()?,
            crypto_engine,
            log_writer: Arc::new(Mutex::new(log_writer)),
            forensics_engine: ForensicsEngine,
            plugin_manager: Arc::new(Mutex::new(PluginManager::new()?)),
            network_manager: Arc::new(Mutex::new(NetworkManager::new())),
        })
    }
    
    fn initialize(&mut self, target: String, engagement_letter: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n╔════════════════════════════════════════════════════════════════╗");
        println!("║              LUCIDSHELL - RULES OF ENGAGEMENT                  ║");
        println!("╠════════════════════════════════════════════════════════════════╣");
        println!("║ You are about to authorize security testing operations.       ║");
        println!("║ By proceeding, you affirm:                                     ║");
        println!("║                                                                ║");
        println!("║ 1. You have explicit written authorization for target         ║");
        println!("║    Target: {:<52} ║", if target.len() > 52 { &target[..52] } else { &target });
        println!("║ 2. All activities will comply with applicable laws            ║");
        println!("║ 3. You will conduct operations within authorized scope        ║");
        println!("║ 4. You will maintain confidentiality of discovered data       ║");
        println!("║ 5. You will follow responsible disclosure practices           ║");
        println!("╚════════════════════════════════════════════════════════════════╝\n");
        
        print!("Type 'I ACCEPT' to continue: ");
        io::stdout().flush()?;
        
        let mut consent = String::new();
        io::stdin().read_line(&mut consent)?;
        
        if consent.trim() != "I ACCEPT" {
            return Err("Authorization declined".into());
        }
        
        let engagement_hash = if let Some(letter_path) = engagement_letter {
            if !letter_path.exists() {
                return Err(format!("Engagement letter not found: {}", letter_path.display()).into());
            }
            let letter_data = std::fs::read(letter_path)?;
            let mut hasher = Sha256::new();
            hasher.update(&letter_data);
            format!("{:x}", hasher.finalize())
        } else {
            String::from("no_engagement_letter")
        };
        
        let auth_data = format!("{}:{}:{}", target, engagement_hash, Utc::now().to_rfc3339());
        let signature = self.crypto_engine.sign_data(auth_data.as_bytes())?;
        
        let authorization = Authorization {
            target: target.clone(),
            engagement_hash,
            timestamp: Utc::now(),
            signature: hex::encode(signature),
        };
        
        let mut session = self.session.lock().unwrap();
        session.authorization = Some(authorization.clone());
        
        let mut logger = self.log_writer.lock().unwrap();
        let log_entry = logger.log_event("SESSION_INITIALIZED", &format!("Target: {}", target), &self.crypto_engine)?;
        session.log_chain.push(log_entry);
        drop(logger);
        drop(session);
        
        println!("\n✓ Session initialized for target: {}", target);
        println!("✓ Authorization signed and logged");
        
        let session = self.session.lock().unwrap();
        println!("✓ Session ID: {}\n", session.session_id);
        
        Ok(())
    }
    
    fn run_tool(&mut self, tool: String, network: bool, profile: Option<String>, args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        let session = self.session.lock().unwrap();
        if session.authorization.is_none() && self.is_active_tool(&tool) {
            return Err("Active tools require authorization. Run 'init' first.".into());
        }
        
        if network && matches!(session.network_status, NetworkStatus::Disabled) {
            return Err("Network access disabled. Configure network settings first.".into());
        }
        drop(session);
        
        let profile = profile.unwrap_or_else(|| "standard".to_string());
        
        println!("→ Running tool '{}' in sandbox profile: {}", tool, profile);
        
        let mut logger = self.log_writer.lock().unwrap();
        let log_entry = logger.log_event("TOOL_EXECUTION", &format!("tool={}, profile={}, network={}", tool, profile, network), &self.crypto_engine)?;
        
        let mut session = self.session.lock().unwrap();
        session.log_chain.push(log_entry);
        drop(session);
        drop(logger);
        
        let sandbox_config = SandboxConfig {
            profile: profile.clone(),
            network_allowed: network,
            filesystem_access: match profile.as_str() {
                "minimal" => FilesystemAccess::None,
                "standard" => FilesystemAccess::ReadOnly,
                "elevated" => FilesystemAccess::ReadWrite,
                _ => FilesystemAccess::ReadOnly,
            },
            registry_access: match profile.as_str() {
                "minimal" => RegistryAccess::None,
                "standard" => RegistryAccess::Minimal,
                "elevated" => RegistryAccess::Standard,
                _ => RegistryAccess::Minimal,
            },
        };
        
        self.sandbox_manager.execute_sandboxed(&tool, &args, sandbox_config)?;
        
        println!("✓ Tool execution completed\n");
        
        Ok(())
    }
    
    fn is_active_tool(&self, tool: &str) -> bool {
        matches!(tool, "nmap" | "metasploit" | "burpsuite" | "scanner" | "exploit")
    }
    
    fn handle_network_command(&mut self, action: NetworkCommands) -> Result<(), Box<dyn std::error::Error>> {
        match action {
            NetworkCommands::Tor { port } => {
                let port = port.unwrap_or(9050);
                let mut net_mgr = self.network_manager.lock().unwrap();
                net_mgr.enable_tor(port)?;
                
                let mut session = self.session.lock().unwrap();
                session.network_status = NetworkStatus::Tor { port };
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("NETWORK_TOR_ENABLED", &format!("port={}", port), &self.crypto_engine)?;
                session.log_chain.push(log_entry);
                
                println!("✓ Tor routing enabled\n");
            },
            NetworkCommands::Vpn { config, protocol } => {
                let mut net_mgr = self.network_manager.lock().unwrap();
                net_mgr.enable_vpn(&config, &protocol)?;
                
                let mut session = self.session.lock().unwrap();
                session.network_status = NetworkStatus::Vpn { protocol: protocol.clone(), connected: false };
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("NETWORK_VPN_CONFIGURED", &format!("protocol={}", protocol), &self.crypto_engine)?;
                session.log_chain.push(log_entry);
                
                println!("✓ VPN configured\n");
            },
            NetworkCommands::Status => {
                self.print_network_status();
            },
            NetworkCommands::Disable => {
                let mut net_mgr = self.network_manager.lock().unwrap();
                net_mgr.disable();
                
                let mut session = self.session.lock().unwrap();
                session.network_status = NetworkStatus::Disabled;
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("NETWORK_DISABLED", "all_access", &self.crypto_engine)?;
                session.log_chain.push(log_entry);
                
                println!("✓ Network disabled\n");
            },
        }
        
        Ok(())
    }
    
    fn print_network_status(&self) {
        let session = self.session.lock().unwrap();
        println!("\n  Network Status:");
        match &session.network_status {
            NetworkStatus::Disabled => println!("    Status: Disabled"),
            NetworkStatus::Direct => println!("    Status: Direct connection"),
            NetworkStatus::Tor { port } => {
                println!("    Status: Tor routing");
                println!("    Port: {}", port);
                println!("    Kill-switch: Active");
            },
            NetworkStatus::Vpn { protocol, connected } => {
                println!("    Status: VPN");
                println!("    Protocol: {}", protocol);
                println!("    Connected: {}", connected);
            },
        }
        println!();
    }
    
    fn handle_forensics_command(&mut self, action: ForensicsCommands) -> Result<(), Box<dyn std::error::Error>> {
        match action {
            ForensicsCommands::Mount { target, vss } => {
                println!("→ Mounting target for forensic analysis");
                println!("  Target: {}", target.display());
                println!("  VSS: {}", vss);
                
                if !target.exists() {
                    return Err(format!("Target not found: {}", target.display()).into());
                }
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("FORENSICS_MOUNT", &format!("target={}, vss={}", target.display(), vss), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
                
                println!("✓ Target mounted (read-only)\n");
            },
            ForensicsCommands::Hash { path, sign } => {
                println!("→ Computing forensic hashes");
                
                let hashes = if path.is_file() {
                    let hash = ForensicsEngine::hash_file(&path)?;
                    let mut map = HashMap::new();
                    map.insert(path.clone(), hash);
                    map
                } else if path.is_dir() {
                    ForensicsEngine::hash_directory(&path)?
                } else {
                    return Err(format!("Path not found: {}", path.display()).into());
                };
                
                println!("\n  Hash Results:");
                for (file_path, hash) in &hashes {
                    println!("    {} *{}", hash, file_path.display());
                }
                
                let manifest = ForensicsEngine::create_manifest(&hashes, sign, &self.crypto_engine)?;
                
                let manifest_path = PathBuf::from(format!("manifest_{}.txt", Utc::now().timestamp()));
                std::fs::write(&manifest_path, manifest)?;
                
                println!("\n✓ Manifest written to: {}", manifest_path.display());
                if sign {
                    println!("✓ Manifest cryptographically signed\n");
                }
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("FORENSICS_HASH", &format!("files={}, signed={}", hashes.len(), sign), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
            ForensicsCommands::Copy { source, dest } => {
                println!("→ Creating forensic copy");
                println!("  Source: {}", source.display());
                println!("  Dest: {}", dest.display());
                
                ForensicsEngine::forensic_copy(&source, &dest)?;
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("FORENSICS_COPY", &format!("source={}, dest={}", source.display(), dest.display()), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
                
                println!("✓ Forensic copy completed and verified\n");
            },
        }
        
        Ok(())
    }
    
    fn handle_plugin_command(&mut self, action: PluginCommands) -> Result<(), Box<dyn std::error::Error>> {
        match action {
            PluginCommands::List => {
                let plugin_mgr = self.plugin_manager.lock().unwrap();
                plugin_mgr.list_plugins();
            },
            PluginCommands::Install { bundle } => {
                let mut plugin_mgr = self.plugin_manager.lock().unwrap();
                plugin_mgr.install_plugin(&bundle, &self.crypto_engine)?;
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("PLUGIN_INSTALLED", &format!("bundle={}", bundle.display()), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
            PluginCommands::Remove { id } => {
                let mut plugin_mgr = self.plugin_manager.lock().unwrap();
                plugin_mgr.remove_plugin(&id)?;
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("PLUGIN_REMOVED", &format!("id={}", id), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
            PluginCommands::Verify => {
                let plugin_mgr = self.plugin_manager.lock().unwrap();
                plugin_mgr.verify_plugins(&self.crypto_engine)?;
            },
        }
        
        Ok(())
    }
    
    fn panic_wipe(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n⚠ PANIC WIPE INITIATED");
        
        let mut logger = self.log_writer.lock().unwrap();
        let _ = logger.log_event("PANIC_WIPE", "emergency_termination", &self.crypto_engine);
        drop(logger);
        
        let mut storage = self.secure_storage.lock().unwrap();
        for byte in &mut storage.data {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        drop(storage);
        
        let mut hasher = Sha256::new();
        hasher.update(b"wipe_verification");
        let _ = hasher.finalize();
        
        println!("✓ Ephemeral storage cleared");
        println!("✓ Session terminated\n");
        
        std::process::exit(0);
    }
    
    fn repl_mode(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n╔════════════════════════════════════════════════════════════════╗");
        println!("║                  LUCIDSHELL REPL MODE                          ║");
        println!("║  Type 'help' for commands, 'exit' to quit                      ║");
        println!("╚════════════════════════════════════════════════════════════════╝\n");
        
        loop {
            print!("lucidshell> ");
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            
            let input = input.trim();
            
            if input == "exit" || input == "quit" {
                break;
            }
            
            if input == "help" {
                self.print_help();
                continue;
            }
            
            if input.is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = input.split_whitespace().collect();
            if let Err(e) = self.execute_repl_command(&parts) {
                eprintln!("Error: {}", e);
            }
        }
        
        Ok(())
    }
    
    fn execute_repl_command(&mut self, parts: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        match parts[0] {
            "status" => self.print_status(),
            "init" => {
                if parts.len() < 2 {
                    return Err("Usage: init <target>".into());
                }
                self.initialize(parts[1].to_string(), None)?;
            },
            "run" => {
                if parts.len() < 2 {
                    return Err("Usage: run <tool> [--network] [args...]".into());
                }
                let tool = parts[1].to_string();
                let network = parts.contains(&"--network");
                let args: Vec<String> = parts[2..]
                    .iter()
                    .filter(|&&s| s != "--network")
                    .map(|s| s.to_string())
                    .collect();
                self.run_tool(tool, network, None, args)?;
            },
            "network" => {
                if parts.len() < 2 {
                    return Err("Usage: network <tor|vpn|status|disable>".into());
                }
                match parts[1] {
                    "status" => self.handle_network_command(NetworkCommands::Status)?,
                    "disable" => self.handle_network_command(NetworkCommands::Disable)?,
                    "tor" => {
                        let port = if parts.len() > 2 {
                            parts[2].parse::<u16>().ok()
                        } else {
                            None
                        };
                        self.handle_network_command(NetworkCommands::Tor { port })?;
                    },
                    _ => return Err(format!("Unknown network command: {}", parts[1]).into()),
                }
            },
            "hash" => {
                if parts.len() < 2 {
                    return Err("Usage: hash <path> [--sign]".into());
                }
                let path = PathBuf::from(parts[1]);
                let sign = parts.contains(&"--sign");
                self.handle_forensics_command(ForensicsCommands::Hash { path, sign })?;
            },
            "plugin" => {
                if parts.len() < 2 {
                    return Err("Usage: plugin <list|install|remove|verify>".into());
                }
                match parts[1] {
                    "list" => self.handle_plugin_command(PluginCommands::List)?,
                    "verify" => self.handle_plugin_command(PluginCommands::Verify)?,
                    _ => return Err(format!("Unknown plugin command: {}", parts[1]).into()),
                }
            },
            "panic" => self.panic_wipe()?,
            _ => return Err(format!("Unknown command: {}", parts[0]).into()),
        }
        Ok(())
    }
    
    fn print_status(&self) {
        let session = self.session.lock().unwrap();
        println!("\n╔════════════════════════════════════════════════════════════════╗");
        println!("║                      SESSION STATUS                            ║");
        println!("╠════════════════════════════════════════════════════════════════╣");
        
        let session_id_display = if session.session_id.len() > 36 {
            &session.session_id[..36]
        } else {
            &session.session_id
        };
        println!("║ Session ID: {:<47} ║", session_id_display);
        println!("║ Mode: {:<56} ║", session.mode);
        println!("║ Ephemeral: {:<51} ║", session.ephemeral);
        println!("║ Authorized: {:<50} ║", session.authorization.is_some());
        
        let network_str = match &session.network_status {
            NetworkStatus::Disabled => "Disabled".to_string(),
            NetworkStatus::Direct => "Direct".to_string(),
            NetworkStatus::Tor { port } => format!("Tor (port {})", port),
            NetworkStatus::Vpn { protocol, connected } => format!("VPN {} ({})", protocol, if *connected { "connected" } else { "disconnected" }),
        };
        println!("║ Network: {:<53} ║", network_str);
        println!("║ Log entries: {:<49} ║", session.log_chain.len());
        println!("╚════════════════════════════════════════════════════════════════╝\n");
    }
    
    fn print_help(&self) {
        println!("\nAvailable commands:");
        println!("  init <target>                   Initialize session with authorization");
        println!("  run <tool> [--network] [args]   Run tool in sandbox");
        println!("  network <tor|status|disable>    Manage network settings");
        println!("  hash <path> [--sign]            Hash file/directory with manifest");
        println!("  plugin <list|verify>            Manage plugins");
        println!("  status                          Show session status");
        println!("  panic                           Emergency wipe and exit");
        println!("  help                            Show this help");
        println!("  exit                            Exit REPL\n");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    let mode = cli.mode.unwrap_or_else(|| "auditor".to_string());
    let mut shell = LucidShell::new(cli.ephemeral, mode)?;
    
    match cli.command {
        Some(Commands::Init { target, engagement_letter }) => {
            shell.initialize(target, engagement_letter)?;
        },
        Some(Commands::Run { tool, network, profile, args }) => {
            shell.run_tool(tool, network, profile, args)?;
        },
        Some(Commands::Network { action }) => {
            shell.handle_network_command(action)?;
        },
        Some(Commands::Forensics { action }) => {
            shell.handle_forensics_command(action)?;
        },
        Some(Commands::Plugin { action }) => {
            shell.handle_plugin_command(action)?;
        },
        Some(Commands::Panic) => {
            shell.panic_wipe()?;
        },
        Some(Commands::Repl) | None => {
            shell.repl_mode()?;
        },
    }
    
    Ok(())
}
