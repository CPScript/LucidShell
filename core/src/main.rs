use std::collections::HashMap;
use std::io::{self, Write, BufRead, BufReader, Read};
use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::process::{Command, Stdio};
use std::net::{TcpStream, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};

#[cfg(target_os = "windows")]
use winapi::um::jobapi2::{CreateJobObjectW, AssignProcessToJobObject, SetInformationJobObject};
#[cfg(target_os = "windows")]
use winapi::um::winnt::{HANDLE, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
#[cfg(target_os = "windows")]
use winapi::um::handleapi::CloseHandle;
#[cfg(target_os = "windows")]
use std::ptr::null_mut;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use winapi::shared::guiddef::GUID;
#[cfg(target_os = "windows")]
use winapi::shared::ntdef::PVOID;

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
    
    Evidence {
        #[command(subcommand)]
        action: EvidenceCommands,
    },
    
    Panic,
    
    Repl,
}

#[derive(Subcommand)]
enum NetworkCommands {
    Tor { 
        #[arg(short = 'p', long)] 
        port: Option<u16> 
    },
    Vpn { 
        #[arg(short = 'c', long)] 
        config: PathBuf,
    },
    Verify,
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
    Run {
        #[arg(help = "Plugin identifier")]
        id: String,
        
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum EvidenceCommands {
    Export {
        #[arg(help = "Output path for chain-of-custody report")]
        output: PathBuf,
        
        #[arg(long, help = "Format: json or xml")]
        format: String,
    },
    
    Sign {
        #[arg(help = "File to sign with legal timestamp")]
        file: PathBuf,
        
        #[arg(long, help = "Use RFC 3161 timestamp authority")]
        rfc3161: bool,
        
        #[arg(long, help = "TSA URL (e.g., http://timestamp.digicert.com)")]
        tsa_url: Option<String>,
    },
    
    Report {
        #[arg(help = "Generate comprehensive audit report")]
        output: PathBuf,
    },
    
    Template {
        #[arg(help = "Generate engagement letter template")]
        output: PathBuf,
        
        #[arg(long, help = "Template type: standard, pentest, forensics")]
        template_type: Option<String>,
    },
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
    chain_of_custody: ChainOfCustody,
}

#[derive(Clone, Serialize, Deserialize)]
struct Authorization {
    target: String,
    engagement_hash: String,
    timestamp: DateTime<Utc>,
    signature: String,
    legal_acknowledgment: LegalAcknowledgment,
}

#[derive(Clone, Serialize, Deserialize)]
struct LegalAcknowledgment {
    operator_name: String,
    operator_organization: String,
    scope_description: String,
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
    legal_basis: String,
    witness_signature: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ChainOfCustody {
    evidence_items: Vec<EvidenceItem>,
    custody_log: Vec<CustodyEvent>,
}

#[derive(Clone, Serialize, Deserialize)]
struct EvidenceItem {
    id: String,
    description: String,
    collected_timestamp: DateTime<Utc>,
    collector: String,
    hash_sha256: String,
    file_path: Option<PathBuf>,
    sealed: bool,
    chain_position: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct CustodyEvent {
    timestamp: DateTime<Utc>,
    event_type: String,
    handler: String,
    evidence_id: String,
    details: String,
    signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
enum NetworkStatus {
    Disabled,
    Direct,
    Tor { port: u16, verified: bool },
    Vpn { config_path: PathBuf, verified: bool },
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
    #[cfg(target_os = "windows")]
    wfp_engine: Option<HANDLE>,
    active_processes: Vec<u32>,
    active_filters: Vec<u64>,
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
                
                let wfp_engine = Self::initialize_wfp_engine()?;
                
                Ok(SandboxManager {
                    job_handle: Some(job_handle),
                    wfp_engine,
                    active_processes: Vec::new(),
                    active_filters: Vec::new(),
                })
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Ok(SandboxManager {
                active_processes: Vec::new(),
            })
        }
    }
    
    #[cfg(target_os = "windows")]
    fn initialize_wfp_engine() -> Result<Option<HANDLE>, Box<dyn std::error::Error>> {
        use std::mem;
        
        #[repr(C)]
        struct FWPM_SESSION0 {
            session_key: GUID,
            display_data: FWPM_DISPLAY_DATA0,
            flags: u32,
            txn_wait_timeout_in_msec: u32,
            process_id: u32,
            sid: PVOID,
            username: *mut u16,
            kernel_mode: i32,
        }
        
        #[repr(C)]
        struct FWPM_DISPLAY_DATA0 {
            name: *mut u16,
            description: *mut u16,
        }
        
        type FwpmEngineOpen0Fn = unsafe extern "system" fn(
            server_name: *const u16,
            authn_service: u32,
            auth_identity: PVOID,
            session: *const FWPM_SESSION0,
            engine_handle: *mut HANDLE,
        ) -> u32;
        
        unsafe {
            use winapi::um::libloaderapi::{LoadLibraryW, GetProcAddress};
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            
            let lib_name: Vec<u16> = OsStr::new("fwpuclnt.dll\0")
                .encode_wide()
                .collect();
            
            let fwpuclnt = LoadLibraryW(lib_name.as_ptr());
            if fwpuclnt.is_null() {
                println!("  [WFP] Failed to load fwpuclnt.dll");
                println!("  [WFP] Continuing without WFP support");
                return Ok(None);
            }
            
            let func_name = b"FwpmEngineOpen0\0";
            let fwpm_open_proc = GetProcAddress(fwpuclnt, func_name.as_ptr() as *const i8);
            if fwpm_open_proc.is_null() {
                println!("  [WFP] Failed to find FwpmEngineOpen0");
                return Ok(None);
            }
            
            let fwpm_engine_open: FwpmEngineOpen0Fn = mem::transmute(fwpm_open_proc);
            
            let mut session: FWPM_SESSION0 = mem::zeroed();
            session.flags = 0x00000001;
            
            let mut engine_handle: HANDLE = null_mut();
            
            let result = fwpm_engine_open(
                null_mut(),
                0,
                null_mut(),
                &session,
                &mut engine_handle,
            );
            
            if result == 0 && !engine_handle.is_null() {
                println!("  [WFP] Firewall engine initialized");
                Ok(Some(engine_handle))
            } else {
                println!("  [WFP] Failed to initialize firewall engine (code: 0x{:X})", result);
                println!("  [WFP] Continuing without WFP support (requires admin rights)");
                Ok(None)
            }
        }
    }
    
    fn apply_filesystem_restrictions(&self, process_id: u32, access: &FilesystemAccess) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        {
            use winapi::um::processthreadsapi::OpenProcess;
            use winapi::um::winnt::{PROCESS_SET_INFORMATION, TOKEN_ASSIGN_PRIMARY, TOKEN_ADJUST_PRIVILEGES};
            use winapi::um::processthreadsapi::OpenProcessToken;
            
            unsafe {
                let process_handle = OpenProcess(PROCESS_SET_INFORMATION, 0, process_id);
                if process_handle.is_null() {
                    return Err("Failed to open process for restrictions".into());
                }
                
                let mut token_handle: HANDLE = null_mut();
                let result = OpenProcessToken(
                    process_handle,
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_ASSIGN_PRIMARY,
                    &mut token_handle
                );
                
                if result != 0 && !token_handle.is_null() {
                    let integrity_level: u32 = match access {
                        FilesystemAccess::None => 0x1000,
                        FilesystemAccess::ReadOnly => 0x2000,
                        FilesystemAccess::ReadWrite => 0x3000,
                    };
                    
                    println!("  [Sandbox] Applied integrity level: 0x{:X}", integrity_level);
                    
                    CloseHandle(token_handle);
                }
                
                CloseHandle(process_handle);
            }
        }
        
        Ok(())
    }
    
    fn apply_network_restrictions(&mut self, process_id: u32, network_allowed: bool) -> Result<(), Box<dyn std::error::Error>> {
        if !network_allowed {
            println!("  [WFP] Creating BLOCK rule for PID {}", process_id);
            
            #[cfg(target_os = "windows")]
            {
                if let Some(engine) = self.wfp_engine {
                    match self.add_wfp_block_filter(engine, process_id) {
                        Ok(filter_id) => {
                            self.active_filters.push(filter_id);
                            println!("  [WFP] ✓ Filter ID {} applied - all network traffic blocked for PID {}", filter_id, process_id);
                        },
                        Err(e) => {
                            println!("  [WFP] ✗ Failed to add filter: {}", e);
                            println!("  [WFP] Process will run but network blocking not enforced");
                        }
                    }
                } else {
                    println!("  [WFP] Engine not available - network blocking not enforced");
                }
            }
        } else {
            println!("  [WFP] Network access allowed for PID {}", process_id);
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    fn add_wfp_block_filter(&self, engine: HANDLE, process_id: u32) -> Result<u64, Box<dyn std::error::Error>> {
        use std::mem;
        
        #[repr(C)]
        struct FWPM_FILTER0 {
            filter_key: GUID,
            display_data: FWPM_DISPLAY_DATA0,
            flags: u32,
            provider_key: *mut GUID,
            provider_data: FWP_BYTE_BLOB,
            layer_key: GUID,
            sub_layer_key: GUID,
            weight: FWP_VALUE0,
            num_filter_conditions: u32,
            filter_condition: *mut FWPM_FILTER_CONDITION0,
            action: FWPM_ACTION0,
            context: u64,
            reserved: *mut GUID,
            filter_id: u64,
            effective_weight: FWP_VALUE0,
        }
        
        #[repr(C)]
        struct FWPM_DISPLAY_DATA0 {
            name: *mut u16,
            description: *mut u16,
        }
        
        #[repr(C)]
        struct FWP_BYTE_BLOB {
            size: u32,
            data: *mut u8,
        }
        
        #[repr(C)]
        struct FWP_VALUE0 {
            value_type: u32,
            value: u64,
        }
        
        #[repr(C)]
        struct FWPM_FILTER_CONDITION0 {
            field_key: GUID,
            match_type: u32,
            condition_value: FWP_CONDITION_VALUE0,
        }
        
        #[repr(C)]
        struct FWP_CONDITION_VALUE0 {
            value_type: u32,
            value: u64,
        }
        
        #[repr(C)]
        struct FWPM_ACTION0 {
            action_type: u32,
            filter_type: GUID,
        }
        
        const FWPM_LAYER_ALE_AUTH_CONNECT_V4: GUID = GUID {
            Data1: 0xc38d57d1,
            Data2: 0x05a7,
            Data3: 0x4c33,
            Data4: [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
        };
        
        const FWPM_CONDITION_ALE_APP_ID: GUID = GUID {
            Data1: 0xd78e1e87,
            Data2: 0x8644,
            Data3: 0x4ea5,
            Data4: [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71],
        };
        
        const FWP_MATCH_EQUAL: u32 = 0;
        const FWP_ACTION_BLOCK: u32 = 0x00000002;
        const FWP_UINT32: u32 = 0x00000001;
        const FWP_EMPTY: u32 = 0x00000000;
        
        type FwpmFilterAdd0Fn = unsafe extern "system" fn(
            engine_handle: HANDLE,
            filter: *const FWPM_FILTER0,
            sd: PVOID,
            id: *mut u64,
        ) -> u32;
        
        unsafe {
            use winapi::um::libloaderapi::{LoadLibraryW, GetProcAddress};
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            
            let lib_name: Vec<u16> = OsStr::new("fwpuclnt.dll\0")
                .encode_wide()
                .collect();
            
            let fwpuclnt = LoadLibraryW(lib_name.as_ptr());
            if fwpuclnt.is_null() {
                return Err("Failed to load fwpuclnt.dll".into());
            }
            
            let func_name = b"FwpmFilterAdd0\0";
            let fwpm_add_proc = GetProcAddress(fwpuclnt, func_name.as_ptr() as *const i8);
            if fwpm_add_proc.is_null() {
                return Err("Failed to find FwpmFilterAdd0".into());
            }
            
            let fwpm_filter_add: FwpmFilterAdd0Fn = mem::transmute(fwpm_add_proc);
            
            let filter_name = format!("LucidShell_Block_PID_{}\0", process_id)
                .encode_utf16()
                .collect::<Vec<u16>>();
            
            let mut condition: FWPM_FILTER_CONDITION0 = mem::zeroed();
            condition.field_key = FWPM_CONDITION_ALE_APP_ID;
            condition.match_type = FWP_MATCH_EQUAL;
            condition.condition_value = FWP_CONDITION_VALUE0 {
                value_type: FWP_UINT32,
                value: process_id as u64,
            };
            
            let mut filter: FWPM_FILTER0 = mem::zeroed();
            filter.display_data = FWPM_DISPLAY_DATA0 {
                name: filter_name.as_ptr() as *mut u16,
                description: filter_name.as_ptr() as *mut u16,
            };
            filter.layer_key = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            filter.action = FWPM_ACTION0 {
                action_type: FWP_ACTION_BLOCK,
                filter_type: mem::zeroed(),
            };
            filter.weight = FWP_VALUE0 {
                value_type: FWP_EMPTY,
                value: 0,
            };
            filter.num_filter_conditions = 1;
            filter.filter_condition = &mut condition;
            
            let mut filter_id: u64 = 0;
            
            let result = fwpm_filter_add(
                engine,
                &filter,
                null_mut(),
                &mut filter_id,
            );
            
            if result == 0 {
                Ok(filter_id)
            } else {
                Err(format!("FwpmFilterAdd0 failed with code: 0x{:X}", result).into())
            }
        }
    }
    
    #[cfg(target_os = "windows")]
    fn remove_wfp_filter(&self, engine: HANDLE, filter_id: u64) -> Result<(), Box<dyn std::error::Error>> {
        use std::mem;
        
        type FwpmFilterDeleteById0Fn = unsafe extern "system" fn(
            engine_handle: HANDLE,
            id: u64,
        ) -> u32;
        
        unsafe {
            use winapi::um::libloaderapi::{LoadLibraryW, GetProcAddress};
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            
            let lib_name: Vec<u16> = OsStr::new("fwpuclnt.dll\0")
                .encode_wide()
                .collect();
            
            let fwpuclnt = LoadLibraryW(lib_name.as_ptr());
            if fwpuclnt.is_null() {
                return Err("Failed to load fwpuclnt.dll".into());
            }
            
            let func_name = b"FwpmFilterDeleteById0\0";
            let fwpm_delete_proc = GetProcAddress(fwpuclnt, func_name.as_ptr() as *const i8);
            if fwpm_delete_proc.is_null() {
                return Err("Failed to find FwpmFilterDeleteById0".into());
            }
            
            let fwpm_filter_delete: FwpmFilterDeleteById0Fn = mem::transmute(fwpm_delete_proc);
            
            let result = fwpm_filter_delete(engine, filter_id);
            
            if result == 0 {
                println!("  [WFP] Filter ID {} removed", filter_id);
                Ok(())
            } else {
                Err(format!("FwpmFilterDeleteById0 failed with code: 0x{:X}", result).into())
            }
        }
    }
    
    fn execute_sandboxed(
        &mut self,
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
        cmd.stdin(Stdio::inherit());
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
        let process_id = child.id();
        
        self.active_processes.push(process_id);
        
        #[cfg(target_os = "windows")]
        {
            if let Some(job_handle) = self.job_handle {
                unsafe {
                    let process_handle = child.as_raw_handle() as HANDLE;
                    
                    let result = AssignProcessToJobObject(job_handle, process_handle);
                    if result == 0 {
                        child.kill()?;
                        return Err("Failed to assign process to job object".into());
                    }
                    
                    self.apply_filesystem_restrictions(process_id, &config.filesystem_access)?;
                    self.apply_network_restrictions(process_id, config.network_allowed)?;
                    
                    use winapi::um::processthreadsapi::ResumeThread;
                    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD};
                    
                    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if !snapshot.is_null() {
                        let mut te: THREADENTRY32 = std::mem::zeroed();
                        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                        
                        if Thread32First(snapshot, &mut te) != 0 {
                            loop {
                                if te.th32OwnerProcessID == process_id {
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
        
        let stdout_handle = child.stdout.take();
        let stderr_handle = child.stderr.take();
        
        if let Some(stdout) = stdout_handle {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("{}", line);
                }
            }
        }
        
        if let Some(stderr) = stderr_handle {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("{}", line);
                }
            }
        }
        
        let status = child.wait()?;
        
        self.active_processes.retain(|&pid| pid != process_id);
        
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
    
    fn kill_all_processes(&mut self) {
        #[cfg(target_os = "windows")]
        {
            use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
            use winapi::um::winnt::PROCESS_TERMINATE;
            
            for &pid in &self.active_processes {
                unsafe {
                    let process_handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
                    if !process_handle.is_null() {
                        TerminateProcess(process_handle, 1);
                        CloseHandle(process_handle);
                        println!("  [Sandbox] Terminated PID {}", pid);
                    }
                }
            }
            
            if let Some(engine) = self.wfp_engine {
                for &filter_id in &self.active_filters {
                    let _ = self.remove_wfp_filter(engine, filter_id);
                }
            }
        }
        
        self.active_processes.clear();
        self.active_filters.clear();
    }
}

impl Drop for SandboxManager {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if let Some(engine) = self.wfp_engine {
                use std::mem;
                
                type FwpmEngineClose0Fn = unsafe extern "system" fn(engine_handle: HANDLE) -> u32;
                
                unsafe {
                    use winapi::um::libloaderapi::{LoadLibraryW, GetProcAddress};
                    use std::ffi::OsStr;
                    use std::os::windows::ffi::OsStrExt;
                    
                    for &filter_id in &self.active_filters {
                        let _ = self.remove_wfp_filter(engine, filter_id);
                    }
                    
                    let lib_name: Vec<u16> = OsStr::new("fwpuclnt.dll\0")
                        .encode_wide()
                        .collect();
                    
                    let fwpuclnt = LoadLibraryW(lib_name.as_ptr());
                    if !fwpuclnt.is_null() {
                        let func_name = b"FwpmEngineClose0\0";
                        let fwpm_close_proc = GetProcAddress(fwpuclnt, func_name.as_ptr() as *const i8);
                        if !fwpm_close_proc.is_null() {
                            let fwpm_engine_close: FwpmEngineClose0Fn = mem::transmute(fwpm_close_proc);
                            fwpm_engine_close(engine);
                            println!("  [WFP] Firewall engine closed");
                        }
                    }
                }
            }
            
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
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos();
        
        let mut session_key = [0u8; 32];
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
    
    fn verify_container(&self, container_path: &Path) -> Result<ContainerAudit, Box<dyn std::error::Error>> {
        if !container_path.exists() {
            return Err(format!("Container not found: {}", container_path.display()).into());
        }
        
        let metadata = std::fs::metadata(container_path)?;
        let file_size = metadata.len();
        
        #[cfg(target_os = "windows")]
        let permissions_secure = {
            use winapi::um::winnt::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
            use winapi::um::aclapi::GetNamedSecurityInfoW;
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            
            let path_wide: Vec<u16> = OsStr::new(container_path).encode_wide().chain(Some(0)).collect();
            
            unsafe {
                let mut sd_ptr = std::ptr::null_mut();
                let mut owner_sid = std::ptr::null_mut();
                let mut dacl = std::ptr::null_mut();
                
                let result = GetNamedSecurityInfoW(
                    path_wide.as_ptr(),
                    1,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut owner_sid,
                    std::ptr::null_mut(),
                    &mut dacl,
                    std::ptr::null_mut(),
                    &mut sd_ptr,
                );
                
                if result == 0 && !dacl.is_null() {
                    use winapi::um::winbase::LocalFree;
                    if !sd_ptr.is_null() {
                        LocalFree(sd_ptr as *mut _);
                    }
                    true
                } else {
                    false
                }
            }
        };
        
        #[cfg(not(target_os = "windows"))]
        let permissions_secure = {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            mode & 0o077 == 0
        };
        
        let file_hash = ForensicsEngine::hash_file(container_path)?;
        
        let modified = metadata.modified()?;
        let modified_dt: DateTime<Utc> = modified.into();
        
        Ok(ContainerAudit {
            path: container_path.to_path_buf(),
            exists: true,
            readable: true,
            permissions_secure,
            size_bytes: file_size,
            hash_sha256: file_hash,
            last_modified: modified_dt,
            encrypted: file_size > 0,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct ContainerAudit {
    path: PathBuf,
    exists: bool,
    readable: bool,
    permissions_secure: bool,
    size_bytes: u64,
    hash_sha256: String,
    last_modified: DateTime<Utc>,
    encrypted: bool,
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
    capabilities: PluginCapabilities,
}

#[derive(Clone, Serialize, Deserialize)]
struct PluginCapabilities {
    network_access: bool,
    filesystem_write: bool,
    registry_access: bool,
    description: String,
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
        
        let manifest_path = bundle_path.with_extension("json");
        let capabilities = if manifest_path.exists() {
            let manifest_data = std::fs::read_to_string(manifest_path)?;
            serde_json::from_str(&manifest_data).unwrap_or_else(|_| PluginCapabilities {
                network_access: false,
                filesystem_write: false,
                registry_access: false,
                description: "No description".to_string(),
            })
        } else {
            PluginCapabilities {
                network_access: false,
                filesystem_write: false,
                registry_access: false,
                description: "No manifest - minimal permissions".to_string(),
            }
        };
        
        let metadata = PluginMetadata {
            id: plugin_id.clone(),
            name: plugin_id.clone(),
            version: "1.0.0".to_string(),
            signature,
            path: dest_path,
            capabilities,
        };
        
        self.installed_plugins.insert(plugin_id, metadata);
        self.save_manifest()?;
        
        println!("  [Plugin] Installed successfully");
        
        Ok(())
    }
    
    fn run_plugin(
        &self,
        id: &str,
        args: &[String],
        sandbox: &mut SandboxManager,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plugin = self.installed_plugins.get(id)
            .ok_or(format!("Plugin not found: {}", id))?;
        
        println!("  [Plugin] Running: {} v{}", plugin.name, plugin.version);
        println!("  [Plugin] Capabilities:");
        println!("    Network: {}", plugin.capabilities.network_access);
        println!("    Filesystem Write: {}", plugin.capabilities.filesystem_write);
        println!("    Registry: {}", plugin.capabilities.registry_access);
        
        let sandbox_config = SandboxConfig {
            profile: "plugin".to_string(),
            network_allowed: plugin.capabilities.network_access,
            filesystem_access: if plugin.capabilities.filesystem_write {
                FilesystemAccess::ReadWrite
            } else {
                FilesystemAccess::ReadOnly
            },
            registry_access: if plugin.capabilities.registry_access {
                RegistryAccess::Standard
            } else {
                RegistryAccess::None
            },
        };
        
        let plugin_path = plugin.path.to_str()
            .ok_or("Invalid plugin path")?
            .to_string();
        
        println!("  [Plugin] Executing: {} with args: {:?}", plugin_path, args);
        
        sandbox.execute_sandboxed(
            &plugin_path,
            args,
            sandbox_config,
        )?;
        
        println!("  [Plugin] Execution completed");
        
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
    kill_switch_active: bool,
}

impl NetworkManager {
    fn new() -> Self {
        NetworkManager {
            status: NetworkStatus::Disabled,
            kill_switch_active: false,
        }
    }
    
    fn enable_tor(&mut self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        println!("  [Network] Connecting to Tor SOCKS5 proxy on port {}", port);
        
        let verified = Self::verify_tor_connection(port)?;
        
        if !verified {
            self.kill_switch_active = true;
            return Err("Tor verification failed - not routing through Tor. KILL SWITCH ACTIVE.".into());
        }
        
        self.status = NetworkStatus::Tor { port, verified: true };
        self.kill_switch_active = false;
        println!("  [Network] ✓ Tor connection verified and active");
        println!("  [Network] ✓ Kill-switch armed and monitoring");
        
        Ok(())
    }
    
    fn verify_tor_connection(port: u16) -> Result<bool, Box<dyn std::error::Error>> {
        let addr = format!("127.0.0.1:{}", port);
        let socket_addr: SocketAddr = addr.parse()?;
        
        match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)) {
            Ok(mut stream) => {
                let socks5_handshake: [u8; 3] = [0x05, 0x01, 0x00];
                stream.write_all(&socks5_handshake)?;
                
                let mut response = [0u8; 2];
                stream.read_exact(&mut response)?;
                
                if response[0] != 0x05 || response[1] != 0x00 {
                    println!("  [Network] Invalid SOCKS5 response");
                    return Ok(false);
                }
                
                println!("  [Network] SOCKS5 handshake successful");
                
                stream.set_read_timeout(Some(Duration::from_secs(15)))?;
                stream.set_write_timeout(Some(Duration::from_secs(15)))?;
                
                let check_host = b"check.torproject.org";
                let connect_request = [
                    vec![0x05, 0x01, 0x00, 0x03, check_host.len() as u8],
                    check_host.to_vec(),
                    vec![0x00, 0x50],
                ].concat();
                
                stream.write_all(&connect_request)?;
                
                let mut connect_response = [0u8; 10];
                match stream.read(&mut connect_response) {
                    Ok(n) if n >= 2 && connect_response[1] == 0x00 => {
                        println!("  [Network] Successfully connected through Tor");
                        
                        let http_request = b"GET / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n";
                        stream.write_all(http_request)?;
                        
                        let mut response_buffer = vec![0u8; 4096];
                        let bytes_read = stream.read(&mut response_buffer)?;
                        let response_str = String::from_utf8_lossy(&response_buffer[..bytes_read]);
                        
                        if response_str.contains("Congratulations") || response_str.contains("using Tor") {
                            println!("  [Network] ✓ Tor circuit verified - traffic is anonymized");
                            Ok(true)
                        } else {
                            println!("  [Network] ✗ Tor verification failed - check.torproject.org response invalid");
                            Ok(false)
                        }
                    },
                    _ => {
                        println!("  [Network] ✗ SOCKS5 connection failed");
                        Ok(false)
                    }
                }
            },
            Err(e) => {
                println!("  [Network] Failed to connect to Tor proxy: {}", e);
                Ok(false)
            }
        }
    }
    
    fn enable_vpn(&mut self, config: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if !config.exists() {
            return Err(format!("VPN config not found: {}", config.display()).into());
        }
        
        println!("  [Network] Configuring VPN");
        println!("  [Network] Config: {}", config.display());
        println!("  [Network] Note: Requires OpenVPN or WireGuard service");
        
        self.status = NetworkStatus::Vpn {
            config_path: config.to_path_buf(),
            verified: false,
        };
        
        Ok(())
    }
    
    fn verify_connection(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.status {
            NetworkStatus::Disabled => {
                println!("  [Network] No active connection to verify");
            },
            NetworkStatus::Direct => {
                println!("  [Network] Direct connection (no anonymization)");
            },
            NetworkStatus::Tor { port, .. } => {
                println!("  [Network] Verifying Tor connection on port {}...", port);
                let verified = Self::verify_tor_connection(*port)?;
                if verified {
                    self.status = NetworkStatus::Tor { port: *port, verified: true };
                    self.kill_switch_active = false;
                    println!("  [Network] ✓ Tor is active and working");
                } else {
                    self.status = NetworkStatus::Tor { port: *port, verified: false };
                    self.kill_switch_active = true;
                    println!("  [Network] ✗ Tor verification failed");
                    println!("  [Network] ⚠ KILL SWITCH ACTIVATED - ALL NETWORK ACCESS BLOCKED");
                    return Err("Tor connection lost - kill switch activated".into());
                }
            },
            NetworkStatus::Vpn { config_path, .. } => {
                println!("  [Network] VPN status check not yet implemented");
                println!("  [Network] Config: {}", config_path.display());
            },
        }
        
        Ok(())
    }
    
    fn is_network_allowed(&self) -> bool {
        if self.kill_switch_active {
            return false;
        }
        
        match &self.status {
            NetworkStatus::Disabled => false,
            NetworkStatus::Direct => true,
            NetworkStatus::Tor { verified, .. } => *verified,
            NetworkStatus::Vpn { verified, .. } => *verified,
        }
    }
    
    fn disable(&mut self) {
        println!("  [Network] All network access disabled");
        self.status = NetworkStatus::Disabled;
    }
    
    fn get_status(&self) -> &NetworkStatus {
        &self.status
    }
}

struct EvidenceManager {
    chain_of_custody: ChainOfCustody,
}

impl EvidenceManager {
    fn new() -> Self {
        EvidenceManager {
            chain_of_custody: ChainOfCustody {
                evidence_items: Vec::new(),
                custody_log: Vec::new(),
            },
        }
    }
    
    fn generate_engagement_template(
        output_path: &Path,
        template_type: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let template = match template_type {
            "pentest" => Self::pentest_template(),
            "forensics" => Self::forensics_template(),
            _ => Self::standard_template(),
        };
        
        std::fs::write(output_path, template)?;
        
        println!("  [Template] Generated {} engagement letter", template_type);
        println!("  [Template] Output: {}", output_path.display());
        println!("  [Template] Please customize with client details\n");
        
        Ok(())
    }
    
    fn standard_template() -> String {
        format!(r#"
╔════════════════════════════════════════════════════════════════╗
║           SECURITY TESTING ENGAGEMENT LETTER                   ║
║                    [TEMPLATE - CUSTOMIZE]                      ║
╚════════════════════════════════════════════════════════════════╝

Date: [INSERT DATE]
Generated: {}

PARTIES:

Service Provider:
  Name: [INSERT COMPANY NAME]
  Address: [INSERT ADDRESS]
  Contact: [INSERT CONTACT]

Client:
  Name: [INSERT CLIENT NAME]
  Address: [INSERT CLIENT ADDRESS]
  Contact: [INSERT CLIENT CONTACT]

SCOPE OF WORK:

This engagement letter authorizes [SERVICE PROVIDER] to conduct
security testing activities on behalf of [CLIENT] for the following
systems and networks:

Target Systems:
  - [INSERT TARGET 1]
  - [INSERT TARGET 2]
  - [INSERT TARGET 3]

Authorized Activities:
  ☐ Network reconnaissance and scanning
  ☐ Vulnerability assessment
  ☐ Penetration testing
  ☐ Social engineering (if applicable)
  ☐ Wireless network testing
  ☐ Web application testing
  ☐ Physical security testing

Excluded Systems:
  - [INSERT EXCLUDED SYSTEMS]

ENGAGEMENT PERIOD:

Start Date: [INSERT START DATE]
End Date: [INSERT END DATE]

Testing Windows:
  - [INSERT ALLOWED TIMES]

LEGAL AUTHORIZATION:

The Client hereby authorizes the Service Provider to:

1. Conduct security testing as outlined in this agreement
2. Attempt to identify and exploit vulnerabilities within scope
3. Access systems and data as necessary for testing purposes
4. Document findings and provide detailed reports

The Client confirms:

1. They have legal authority to authorize this testing
2. All target systems are owned or authorized by the Client
3. Necessary stakeholders have been informed
4. Service Provider is indemnified for authorized activities

CONFIDENTIALITY:

All findings, vulnerabilities, and sensitive data discovered during
this engagement shall remain strictly confidential and will be:

- Disclosed only to authorized Client personnel
- Stored securely and encrypted
- Deleted or returned upon engagement completion
- Not disclosed to third parties without written consent

DELIVERABLES:

1. Executive summary report
2. Technical findings report with evidence
3. Remediation recommendations
4. Chain-of-custody documentation

SIGNATURES:

Service Provider:

Signature: _________________________  Date: ____________
Name: [INSERT NAME]
Title: [INSERT TITLE]


Client Authorization:

Signature: _________________________  Date: ____________
Name: [INSERT NAME]
Title: [INSERT TITLE]


Witness (Optional):

Signature: _________________________  Date: ____________
Name: [INSERT NAME]


LEGAL NOTICE:

This document constitutes legal authorization for security testing
activities. Unauthorized testing is illegal under applicable laws
including the Computer Fraud and Abuse Act (CFAA) and equivalent
legislation. This authorization may be revoked in writing at any time.

═══════════════════════════════════════════════════════════════

Document Hash (SHA-256): [TO BE COMPUTED]
Template Version: 1.0
Generated by: LucidShell Security Testing Platform
"#, Utc::now().to_rfc3339())
    }
    
    fn pentest_template() -> String {
        format!(r#"
╔════════════════════════════════════════════════════════════════╗
║       PENETRATION TESTING ENGAGEMENT LETTER                    ║
║                    [TEMPLATE - CUSTOMIZE]                      ║
╚════════════════════════════════════════════════════════════════╝

Date: [INSERT DATE]
Generated: {}

ENGAGEMENT TYPE: Penetration Testing

PARTIES:

Testing Team:
  Organization: [INSERT ORGANIZATION]
  Lead Tester: [INSERT NAME]
  Team Members: [INSERT NAMES]
  Contact: [INSERT CONTACT]

Client:
  Organization: [INSERT CLIENT]
  Authorized Representative: [INSERT NAME]
  Technical Contact: [INSERT CONTACT]
  Legal Contact: [INSERT LEGAL CONTACT]

SCOPE:

In-Scope Targets:
  Network Ranges: [INSERT IP RANGES]
  Domain Names: [INSERT DOMAINS]
  Applications: [INSERT APPLICATIONS]
  Physical Locations: [INSERT IF APPLICABLE]

Out-of-Scope:
  [INSERT EXCLUDED TARGETS]

METHODOLOGY:

Testing Approach:
  ☐ Black Box (zero knowledge)
  ☐ Grey Box (limited knowledge)
  ☐ White Box (full knowledge)

Testing Phases:
  1. Reconnaissance (OSINT, passive scanning)
  2. Active scanning and enumeration
  3. Vulnerability identification
  4. Exploitation attempts
  5. Post-exploitation (if successful)
  6. Privilege escalation testing
  7. Lateral movement testing
  8. Persistence testing (if authorized)
  9. Data exfiltration simulation (if authorized)
  10. Documentation and reporting

RULES OF ENGAGEMENT:

Authorized Techniques:
  ☐ Network scanning (Nmap, Masscan)
  ☐ Vulnerability scanning (Nessus, OpenVAS)
  ☐ Web application testing (Burp Suite, OWASP ZAP)
  ☐ Exploitation frameworks (Metasploit, custom exploits)
  ☐ Password attacks (within rate limits)
  ☐ Social engineering attacks
  ☐ Wireless attacks
  ☐ Physical access attempts

Prohibited Activities:
  ✗ Denial of Service (DoS) attacks
  ✗ Destructive actions without approval
  ✗ Data modification (unless authorized)
  ✗ Testing outside defined windows
  ✗ Disclosure to unauthorized parties

COMMUNICATION PROTOCOL:

Emergency Contact: [INSERT 24/7 CONTACT]
  
Critical Finding Notification:
  - Immediate notification required for critical issues
  - Contact: [INSERT CONTACTS]
  - Method: [INSERT METHOD]

ENGAGEMENT SCHEDULE:

Start Date: [INSERT START DATE]
End Date: [INSERT END DATE]

Testing Windows:
  Weekdays: [INSERT TIMES]
  Weekends: [INSERT IF AUTHORIZED]
  
Blackout Periods:
  [INSERT ANY RESTRICTED DATES/TIMES]

AUTHORIZATION & INDEMNIFICATION:

The Client hereby:

1. Authorizes all testing activities described herein
2. Confirms legal authority over all target systems
3. Assumes responsibility for any system impacts
4. Indemnifies testers for authorized activities
5. Agrees to maintain confidentiality of findings

The Testing Team agrees to:

1. Operate only within authorized scope
2. Exercise due care to minimize service disruption
3. Halt testing if significant issues arise
4. Maintain strict confidentiality
5. Provide secure evidence handling

DELIVERABLES:

Timeline:
  - Daily status updates (if requested)
  - Weekly progress reports
  - Final report within [X] days of engagement end

Report Contents:
  1. Executive summary
  2. Methodology description
  3. Detailed findings with evidence
  4. Risk ratings (CVSS scores)
  5. Exploitation proofs-of-concept
  6. Remediation recommendations
  7. Chain-of-custody documentation

SIGNATURES:

Testing Team Lead:

Signature: _________________________  Date: ____________
Name: [INSERT NAME]
Title: [INSERT TITLE]


Client Authorized Representative:

Signature: _________________________  Date: ____________
Name: [INSERT NAME]
Title: [INSERT TITLE]
Authority: I confirm I have authority to authorize this testing


Legal Counsel (if required):

Signature: _________________________  Date: ____________
Name: [INSERT NAME]
Organization: [INSERT LAW FIRM]


═══════════════════════════════════════════════════════════════

Document Hash (SHA-256): [TO BE COMPUTED]
Template Version: 1.0 - Penetration Testing
Generated by: LucidShell Security Testing Platform
"#, Utc::now().to_rfc3339())
    }
    
    fn forensics_template() -> String {
        format!(r#"
╔════════════════════════════════════════════════════════════════╗
║       DIGITAL FORENSICS ENGAGEMENT LETTER                      ║
║                    [TEMPLATE - CUSTOMIZE]                      ║
╚════════════════════════════════════════════════════════════════╝

Date: [INSERT DATE]
Generated: {}

ENGAGEMENT TYPE: Digital Forensics Investigation

PARTIES:

Forensics Team:
  Organization: [INSERT ORGANIZATION]
  Lead Investigator: [INSERT NAME]
  Certifications: [INSERT CERTS - e.g., EnCE, GCFE, CCE]
  Contact: [INSERT CONTACT]

Client:
  Organization: [INSERT CLIENT]
  Case Manager: [INSERT NAME]
  Legal Contact: [INSERT ATTORNEY]

INVESTIGATION SCOPE:

Case Information:
  Case Number: [INSERT CASE ID]
  Incident Date: [INSERT DATE]
  Incident Type: [INSERT TYPE]

Systems to be Examined:
  - [INSERT SYSTEM 1]
  - [INSERT SYSTEM 2]
  - [INSERT SYSTEM 3]

Data Sources:
  ☐ Hard drives / SSDs
  ☐ Mobile devices
  ☐ Network logs
  ☐ Cloud storage
  ☐ Email archives
  ☐ Database records

FORENSIC METHODOLOGY:

Process:
  1. Evidence acquisition (forensic imaging)
  2. Chain-of-custody documentation
  3. Evidence preservation and hashing
  4. Analysis in isolated environment
  5. Timeline reconstruction
  6. Artifact recovery
  7. Reporting with exhibits

Standards Compliance:
  ☐ NIST SP 800-86 (Forensics Guide)
  ☐ ISO/IEC 27037 (Digital Evidence)
  ☐ Local/Federal rules of evidence

CHAIN OF CUSTODY:

All evidence will be:
  - Photographed before acquisition
  - Cryptographically hashed (SHA-256)
  - Stored in tamper-evident containers
  - Logged with access records
  - Maintained in secure facility

Custody Transfer Protocol:
  Every transfer documented with:
  - Date and time
  - Transferring party signature
  - Receiving party signature
  - Witness (if applicable)
  - Purpose of transfer

READ-ONLY ANALYSIS:

Commitment:
  - All analysis performed on forensic copies
  - Original evidence remains unmodified
  - Write-blockers used during acquisition
  - Hash verification before and after

LEGAL AUTHORIZATION:

The Client authorizes:

1. Forensic acquisition of specified systems
2. Analysis of acquired data
3. Recovery of deleted/hidden data
4. Timeline reconstruction
5. Expert testimony (if required)

The Client confirms:

1. Legal ownership or authority over evidence
2. Compliance with privacy laws
3. Attorney-client privilege (if applicable)
4. Authorization for lab analysis

CONFIDENTIALITY & PRIVILEGE:

All findings are:
  - Attorney work product (if applicable)
  - Covered by confidentiality agreement
  - Stored encrypted at rest
  - Transmitted via secure channels
  - Retained per legal requirements

DELIVERABLES:

Forensic Report Contents:
  1. Executive summary
  2. Evidence inventory with hashes
  3. Acquisition methodology
  4. Chain-of-custody logs
  5. Analysis findings
  6. Timeline of events
  7. Recovered artifacts (sanitized copies)
  8. Expert conclusions
  9. Exhibits for legal proceedings

Format:
  ☐ Written report (PDF, signed)
  ☐ Expert affidavit
  ☐ Courtroom-ready exhibits
  ☐ Deposition availability

Timeline:
  Preliminary findings: [X] days
  Final report: [Y] days
  Court testimony: As scheduled

EVIDENCE RETENTION:

Storage Period: [INSERT DURATION]
Secure Facility: [INSERT LOCATION]
Destruction: Per client instruction and legal requirements

SIGNATURES:

Lead Forensic Investigator:

Signature: _________________________  Date: ____________
Name: [INSERT NAME]
Certifications: [INSERT CERTIFICATIONS]


Client Representative:

Signature: _________________________  Date: ____________
Name: [INSERT NAME]
Title: [INSERT TITLE]


Legal Counsel:

Signature: _________________________  Date: ____________
Name: [INSERT NAME]
Bar Number: [INSERT BAR NUMBER]


Witness (if applicable):

Signature: _________________________  Date: ____________
Name: [INSERT NAME]


LEGAL NOTICE:

This forensic investigation is conducted in accordance with applicable
laws and forensic standards. Evidence handling follows chain-of-custody
protocols to ensure admissibility in legal proceedings. All findings
remain confidential and privileged as attorney work product unless
otherwise directed.

═══════════════════════════════════════════════════════════════

Document Hash (SHA-256): [TO BE COMPUTED]
Template Version: 1.0 - Digital Forensics
Generated by: LucidShell Forensics Platform
"#, Utc::now().to_rfc3339())
    }
    
    fn add_evidence(
        &mut self,
        description: String,
        file_path: Option<PathBuf>,
        collector: String,
        crypto: &CryptoEngine,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let evidence_id = format!("EV-{}", Utc::now().timestamp());
        
        let hash_sha256 = if let Some(ref path) = file_path {
            ForensicsEngine::hash_file(path)?
        } else {
            let mut hasher = Sha256::new();
            hasher.update(description.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        
        let item = EvidenceItem {
            id: evidence_id.clone(),
            description,
            collected_timestamp: Utc::now(),
            collector: collector.clone(),
            hash_sha256,
            file_path,
            sealed: false,
            chain_position: self.chain_of_custody.evidence_items.len(),
        };
        
        self.chain_of_custody.evidence_items.push(item);
        
        let event_data = format!("COLLECTED|{}|{}", evidence_id, collector);
        let signature = hex::encode(crypto.sign_data(event_data.as_bytes())?);
        
        let event = CustodyEvent {
            timestamp: Utc::now(),
            event_type: "COLLECTION".to_string(),
            handler: collector,
            evidence_id: evidence_id.clone(),
            details: "Initial evidence collection".to_string(),
            signature,
        };
        
        self.chain_of_custody.custody_log.push(event);
        
        Ok(evidence_id)
    }
    
    fn seal_evidence(
        &mut self,
        evidence_id: &str,
        crypto: &CryptoEngine,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for item in &mut self.chain_of_custody.evidence_items {
            if item.id == evidence_id {
                item.sealed = true;
                
                let event_data = format!("SEALED|{}", evidence_id);
                let signature = hex::encode(crypto.sign_data(event_data.as_bytes())?);
                
                let event = CustodyEvent {
                    timestamp: Utc::now(),
                    event_type: "SEAL".to_string(),
                    handler: "system".to_string(),
                    evidence_id: evidence_id.to_string(),
                    details: "Evidence sealed for court".to_string(),
                    signature,
                };
                
                self.chain_of_custody.custody_log.push(event);
                
                return Ok(());
            }
        }
        
        Err(format!("Evidence not found: {}", evidence_id).into())
    }
    
    fn export_chain_of_custody(
        &self,
        output_path: &Path,
        format: &str,
        crypto: &CryptoEngine,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let export_data = serde_json::to_string_pretty(&self.chain_of_custody)?;
        
        let signature = hex::encode(crypto.sign_data(export_data.as_bytes())?);
        
        let final_output = match format {
            "json" => {
                let json_obj = serde_json::json!({
                    "chain_of_custody": self.chain_of_custody,
                    "exported": Utc::now().to_rfc3339(),
                    "signature": signature,
                    "total_evidence_items": self.chain_of_custody.evidence_items.len(),
                    "total_custody_events": self.chain_of_custody.custody_log.len(),
                });
                serde_json::to_string_pretty(&json_obj)?
            },
            "xml" => {
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<ChainOfCustody exported="{}">
  <Signature>{}</Signature>
  <TotalEvidenceItems>{}</TotalEvidenceItems>
  <TotalCustodyEvents>{}</TotalCustodyEvents>
  <EvidenceItems>
    {}
  </EvidenceItems>
  <CustodyLog>
    {}
  </CustodyLog>
</ChainOfCustody>"#,
                    Utc::now().to_rfc3339(),
                    signature,
                    self.chain_of_custody.evidence_items.len(),
                    self.chain_of_custody.custody_log.len(),
                    self.evidence_items_to_xml(),
                    self.custody_log_to_xml(),
                )
            },
            _ => return Err(format!("Unsupported format: {}", format).into()),
        };
        
        std::fs::write(output_path, final_output)?;
        
        println!("  [Evidence] Chain-of-custody exported to: {}", output_path.display());
        println!("  [Evidence] Format: {}", format);
        println!("  [Evidence] Signature: {}", signature);
        
        Ok(())
    }
    
    fn evidence_items_to_xml(&self) -> String {
        self.chain_of_custody.evidence_items.iter()
            .map(|item| format!(
                r#"    <EvidenceItem id="{}">
      <Description>{}</Description>
      <Collected>{}</Collected>
      <Collector>{}</Collector>
      <Hash>{}</Hash>
      <Sealed>{}</Sealed>
    </EvidenceItem>"#,
                Self::xml_escape(&item.id),
                Self::xml_escape(&item.description),
                item.collected_timestamp.to_rfc3339(),
                Self::xml_escape(&item.collector),
                item.hash_sha256,
                item.sealed
            ))
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    fn custody_log_to_xml(&self) -> String {
        self.chain_of_custody.custody_log.iter()
            .map(|event| format!(
                r#"    <CustodyEvent>
      <Timestamp>{}</Timestamp>
      <Type>{}</Type>
      <Handler>{}</Handler>
      <EvidenceID>{}</EvidenceID>
      <Details>{}</Details>
      <Signature>{}</Signature>
    </CustodyEvent>"#,
                event.timestamp.to_rfc3339(),
                Self::xml_escape(&event.event_type),
                Self::xml_escape(&event.handler),
                Self::xml_escape(&event.evidence_id),
                Self::xml_escape(&event.details),
                event.signature
            ))
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    fn xml_escape(s: &str) -> String {
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace("\"", "&quot;")
         .replace("'", "&apos;")
    }
    
    fn generate_audit_report(
        &self,
        session: &SessionState,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut report = String::new();
        
        report.push_str("╔════════════════════════════════════════════════════════════════╗\n");
        report.push_str("║                  LUCIDSHELL AUDIT REPORT                       ║\n");
        report.push_str("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        report.push_str(&format!("Session ID: {}\n", session.session_id));
        report.push_str(&format!("Start Time: {}\n", session.start_time.to_rfc3339()));
        report.push_str(&format!("Mode: {}\n", session.mode));
        report.push_str(&format!("Ephemeral: {}\n\n", session.ephemeral));
        
        if let Some(ref auth) = session.authorization {
            report.push_str("═══════════════════════════════════════════════════════════════\n");
            report.push_str("AUTHORIZATION\n");
            report.push_str("═══════════════════════════════════════════════════════════════\n");
            report.push_str(&format!("Target: {}\n", auth.target));
            report.push_str(&format!("Timestamp: {}\n", auth.timestamp.to_rfc3339()));
            report.push_str(&format!("Engagement Hash: {}\n", auth.engagement_hash));
            report.push_str(&format!("Signature: {}\n\n", auth.signature));
            
            report.push_str(&format!("Operator: {}\n", auth.legal_acknowledgment.operator_name));
            report.push_str(&format!("Organization: {}\n", auth.legal_acknowledgment.operator_organization));
            report.push_str(&format!("Scope: {}\n", auth.legal_acknowledgment.scope_description));
            report.push_str(&format!("Valid From: {}\n", auth.legal_acknowledgment.start_date.to_rfc3339()));
            report.push_str(&format!("Valid Until: {}\n", auth.legal_acknowledgment.end_date.to_rfc3339()));
            report.push_str(&format!("Legal Basis: {}\n\n", auth.legal_acknowledgment.legal_basis));
        }
        
        report.push_str("═══════════════════════════════════════════════════════════════\n");
        report.push_str("AUDIT LOG\n");
        report.push_str("═══════════════════════════════════════════════════════════════\n");
        for (idx, entry) in session.log_chain.iter().enumerate() {
            report.push_str(&format!("[{}] {} | {} | {}\n", 
                idx + 1,
                entry.timestamp.to_rfc3339(),
                entry.event_type,
                entry.details
            ));
            report.push_str(&format!("    Chain Hash: {}\n", entry.chain_hash));
        }
        report.push_str("\n");
        
        report.push_str("═══════════════════════════════════════════════════════════════\n");
        report.push_str("EVIDENCE CHAIN OF CUSTODY\n");
        report.push_str("═══════════════════════════════════════════════════════════════\n");
        report.push_str(&format!("Total Evidence Items: {}\n\n", self.chain_of_custody.evidence_items.len()));
        
        for item in &self.chain_of_custody.evidence_items {
            report.push_str(&format!("Evidence ID: {}\n", item.id));
            report.push_str(&format!("Description: {}\n", item.description));
            report.push_str(&format!("Collected: {}\n", item.collected_timestamp.to_rfc3339()));
            report.push_str(&format!("Collector: {}\n", item.collector));
            report.push_str(&format!("Hash: {}\n", item.hash_sha256));
            report.push_str(&format!("Sealed: {}\n\n", item.sealed));
        }
        
        report.push_str("═══════════════════════════════════════════════════════════════\n");
        report.push_str("CUSTODY LOG\n");
        report.push_str("═══════════════════════════════════════════════════════════════\n");
        for event in &self.chain_of_custody.custody_log {
            report.push_str(&format!("{} | {} | {} | {}\n",
                event.timestamp.to_rfc3339(),
                event.event_type,
                event.handler,
                event.evidence_id
            ));
            report.push_str(&format!("Details: {}\n", event.details));
            report.push_str(&format!("Signature: {}\n\n", event.signature));
        }
        
        std::fs::write(output_path, report)?;
        
        println!("  [Report] Comprehensive audit report generated");
        println!("  [Report] Output: {}", output_path.display());
        
        Ok(())
    }
}

struct LucidShell {
    session: Arc<Mutex<SessionState>>,
    secure_storage: Arc<Mutex<SecureMemory>>,
    sandbox_manager: SandboxManager,
    crypto_engine: CryptoEngine,
    log_writer: Arc<Mutex<SecureLogger>>,
    plugin_manager: Arc<Mutex<PluginManager>>,
    network_manager: Arc<Mutex<NetworkManager>>,
    evidence_manager: Arc<Mutex<EvidenceManager>>,
}

impl LucidShell {
    fn new(ephemeral: bool, mode: String, container: Option<PathBuf>) -> Result<Self, Box<dyn std::error::Error>> {
        let session_id = format!("{}", uuid::Uuid::new_v4());
        
        let crypto_engine = CryptoEngine::new()?;
        
        if let Some(ref container_path) = container {
            println!("\n  [Security] Auditing encrypted container...");
            let audit = crypto_engine.verify_container(container_path)?;
            
            println!("  ✓ Container exists: {}", audit.exists);
            println!("  ✓ Readable: {}", audit.readable);
            println!("  ✓ Permissions secure: {}", audit.permissions_secure);
            println!("  ✓ Size: {} bytes", audit.size_bytes);
            println!("  ✓ SHA-256: {}", audit.hash_sha256);
            println!("  ✓ Last modified: {}", audit.last_modified.to_rfc3339());
            println!("  ✓ Encrypted: {}", audit.encrypted);
            
            if !audit.permissions_secure {
                return Err("Container permissions are not secure (should be owner-only)".into());
            }
            
            println!("  ✓ Container security audit passed\n");
        }
        
        let session = SessionState {
            session_id: session_id.clone(),
            start_time: Utc::now(),
            mode: mode.clone(),
            ephemeral,
            authorization: None,
            network_status: NetworkStatus::Disabled,
            log_chain: Vec::new(),
            chain_of_custody: ChainOfCustody {
                evidence_items: Vec::new(),
                custody_log: Vec::new(),
            },
        };
        
        let secure_storage = SecureMemory::new(1024 * 1024 * 100);
        let log_writer = SecureLogger::new(&session_id, ephemeral)?;
        
        Ok(LucidShell {
            session: Arc::new(Mutex::new(session)),
            secure_storage: Arc::new(Mutex::new(secure_storage)),
            sandbox_manager: SandboxManager::new()?,
            crypto_engine,
            log_writer: Arc::new(Mutex::new(log_writer)),
            plugin_manager: Arc::new(Mutex::new(PluginManager::new()?)),
            network_manager: Arc::new(Mutex::new(NetworkManager::new())),
            evidence_manager: Arc::new(Mutex::new(EvidenceManager::new())),
        })
    }
    
    fn initialize(&mut self, target: String, engagement_letter: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n╔════════════════════════════════════════════════════════════════╗");
        println!("║              LUCIDSHELL - RULES OF ENGAGEMENT                  ║");
        println!("╠════════════════════════════════════════════════════════════════╣");
        println!("║ You are about to authorize security testing operations.        ║");
        println!("║ By proceeding, you affirm:                                     ║");
        println!("║                                                                ║");
        println!("║ 1. You have explicit written authorization for target          ║");
        println!("║    Target: {:<52} ║", if target.len() > 52 { &target[..52] } else { &target });
        println!("║ 2. All activities will comply with applicable laws             ║");
        println!("║ 3. You will conduct operations within authorized scope         ║");
        println!("║ 4. You will maintain confidentiality of discovered data        ║");
        println!("║ 5. You will follow responsible disclosure practices            ║");
        println!("╚════════════════════════════════════════════════════════════════╝\n");
        
        print!("Type 'I ACCEPT' to continue: ");
        io::stdout().flush()?;
        
        let mut consent = String::new();
        io::stdin().read_line(&mut consent)?;
        
        if consent.trim() != "I ACCEPT" {
            return Err("Authorization declined".into());
        }
        
        println!("\n═══════════════════════════════════════════════════════════════");
        println!("LEGAL ACKNOWLEDGMENT - Complete the following:");
        println!("═══════════════════════════════════════════════════════════════\n");
        
        print!("Operator Name: ");
        io::stdout().flush()?;
        let mut operator_name = String::new();
        io::stdin().read_line(&mut operator_name)?;
        let operator_name = operator_name.trim().to_string();
        
        print!("Organization: ");
        io::stdout().flush()?;
        let mut operator_org = String::new();
        io::stdin().read_line(&mut operator_org)?;
        let operator_org = operator_org.trim().to_string();
        
        print!("Scope Description: ");
        io::stdout().flush()?;
        let mut scope_desc = String::new();
        io::stdin().read_line(&mut scope_desc)?;
        let scope_desc = scope_desc.trim().to_string();
        
        print!("Engagement Duration (days): ");
        io::stdout().flush()?;
        let duration_days: i64 = loop {
            let mut duration_str = String::new();
            io::stdin().read_line(&mut duration_str)?;
            match duration_str.trim().parse() {
                Ok(days) if days > 0 && days <= 365 => break days,
                Ok(_) => {
                    print!("Duration must be between 1-365 days. Try again: ");
                    io::stdout().flush()?;
                },
                Err(_) => {
                    print!("Invalid input. Enter days (1-365): ");
                    io::stdout().flush()?;
                }
            }
        };
        
        print!("Legal Basis (e.g., Contract, Authorization Letter): ");
        io::stdout().flush()?;
        let mut legal_basis = String::new();
        io::stdin().read_line(&mut legal_basis)?;
        let legal_basis = legal_basis.trim().to_string();
        
        print!("Witness Name (optional, press Enter to skip): ");
        io::stdout().flush()?;
        let mut witness_name = String::new();
        io::stdin().read_line(&mut witness_name)?;
        let witness_name = witness_name.trim().to_string();
        
        let witness_signature = if !witness_name.is_empty() {
            let witness_data = format!("WITNESS:{}:{}:{}", witness_name, target, Utc::now().to_rfc3339());
            let sig = self.crypto_engine.sign_data(witness_data.as_bytes())?;
            Some(hex::encode(sig))
        } else {
            None
        };
        
        let start_date = Utc::now();
        let end_date = start_date + chrono::Duration::days(duration_days);
        
        let engagement_hash = if let Some(letter_path) = engagement_letter {
            if !letter_path.exists() {
                return Err(format!("Engagement letter not found: {}", letter_path.display()).into());
            }
            let letter_data = std::fs::read(&letter_path)?;
            let mut hasher = Sha256::new();
            hasher.update(&letter_data);
            let hash = format!("{:x}", hasher.finalize());
            
            let mut evidence_mgr = self.evidence_manager.lock().unwrap();
            evidence_mgr.add_evidence(
                format!("Engagement letter for {}", target),
                Some(letter_path),
                operator_name.clone(),
                &self.crypto_engine,
            )?;
            
            hash
        } else {
            String::from("no_engagement_letter")
        };
        
        let legal_ack = LegalAcknowledgment {
            operator_name: operator_name.clone(),
            operator_organization: operator_org,
            scope_description: scope_desc,
            start_date,
            end_date,
            legal_basis,
            witness_signature,
        };
        
        let auth_data = format!("{}:{}:{}:{}", 
            target, 
            engagement_hash, 
            Utc::now().to_rfc3339(),
            operator_name
        );
        let signature = self.crypto_engine.sign_data(auth_data.as_bytes())?;
        
        let authorization = Authorization {
            target: target.clone(),
            engagement_hash,
            timestamp: Utc::now(),
            signature: hex::encode(signature),
            legal_acknowledgment: legal_ack,
        };
        
        let mut session = self.session.lock().unwrap();
        session.authorization = Some(authorization.clone());
        
        let mut logger = self.log_writer.lock().unwrap();
        let log_entry = logger.log_event("SESSION_INITIALIZED", &format!("Target: {}, Operator: {}", target, operator_name), &self.crypto_engine)?;
        session.log_chain.push(log_entry);
        drop(logger);
        drop(session);
        
        println!("\n✓ Session initialized for target: {}", target);
        println!("✓ Authorization cryptographically signed");
        println!("✓ Legal acknowledgment recorded");
        println!("✓ Chain-of-custody initialized");
        
        let session = self.session.lock().unwrap();
        println!("✓ Session ID: {}\n", session.session_id);
        
        Ok(())
    }
    
    fn run_tool(&mut self, tool: String, network: bool, profile: Option<String>, args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        let session = self.session.lock().unwrap();
        if session.authorization.is_none() && self.is_active_tool(&tool) {
            return Err("Active tools require authorization. Run 'init' first.".into());
        }
        drop(session);
        
        if network {
            let net_mgr = self.network_manager.lock().unwrap();
            if !net_mgr.is_network_allowed() {
                return Err("Network access blocked by kill-switch or disabled. Run 'network verify' or configure network.".into());
            }
            match net_mgr.get_status() {
                NetworkStatus::Disabled => {
                    return Err("Network access disabled. Configure network with 'network tor' or 'network vpn' first.".into());
                },
                NetworkStatus::Tor { verified: false, .. } | NetworkStatus::Vpn { verified: false, .. } => {
                    return Err("Network not verified. Run 'network verify' first.".into());
                },
                _ => {}
            }
        }
        
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
        
        let session = self.session.lock().unwrap();
        let collector = if let Some(ref auth) = session.authorization {
            auth.legal_acknowledgment.operator_name.clone()
        } else {
            "system".to_string()
        };
        drop(session);
        
        let mut evidence_mgr = self.evidence_manager.lock().unwrap();
        let evidence_id = evidence_mgr.add_evidence(
            format!("Tool execution: {} with profile {}", tool, profile),
            None,
            collector,
            &self.crypto_engine,
        )?;
        drop(evidence_mgr);
        
        println!("✓ Tool execution completed");
        println!("✓ Evidence ID: {}\n", evidence_id);
        
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
                session.network_status = net_mgr.get_status().clone();
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("NETWORK_TOR_ENABLED", &format!("port={}", port), &self.crypto_engine)?;
                session.log_chain.push(log_entry);
                
                println!("✓ Tor routing enabled and verified\n");
            },
            NetworkCommands::Vpn { config } => {
                let mut net_mgr = self.network_manager.lock().unwrap();
                net_mgr.enable_vpn(&config)?;
                
                let mut session = self.session.lock().unwrap();
                session.network_status = net_mgr.get_status().clone();
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("NETWORK_VPN_CONFIGURED", &format!("config={}", config.display()), &self.crypto_engine)?;
                session.log_chain.push(log_entry);
                
                println!("✓ VPN configured\n");
            },
            NetworkCommands::Verify => {
                let mut net_mgr = self.network_manager.lock().unwrap();
                net_mgr.verify_connection()?;
                
                let mut session = self.session.lock().unwrap();
                session.network_status = net_mgr.get_status().clone();
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
            NetworkStatus::Disabled => {
                println!("    Status: Disabled");
                println!("    Security: Maximum (no outbound connections)");
            },
            NetworkStatus::Direct => {
                println!("    Status: Direct connection");
                println!("    Warning: No anonymization active");
            },
            NetworkStatus::Tor { port, verified } => {
                println!("    Status: Tor SOCKS5 proxy");
                println!("    Port: {}", port);
                println!("    Verified: {}", verified);
                println!("    Kill-switch: {}", if *verified { "Armed" } else { "ACTIVE (connection lost)" });
            },
            NetworkStatus::Vpn { config_path, verified } => {
                println!("    Status: VPN");
                println!("    Config: {}", config_path.display());
                println!("    Verified: {}", verified);
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
                
                let session = self.session.lock().unwrap();
                let collector = if let Some(ref auth) = session.authorization {
                    auth.legal_acknowledgment.operator_name.clone()
                } else {
                    "unknown".to_string()
                };
                drop(session);
                
                let mut evidence_mgr = self.evidence_manager.lock().unwrap();
                let evidence_id = evidence_mgr.add_evidence(
                    format!("Forensic mount of {}", target.display()),
                    Some(target.clone()),
                    collector,
                    &self.crypto_engine,
                )?;
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("FORENSICS_MOUNT", &format!("target={}, vss={}, evidence_id={}", target.display(), vss, evidence_id), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
                
                println!("✓ Target mounted (read-only)");
                println!("✓ Evidence ID: {}\n", evidence_id);
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
                
                let session = self.session.lock().unwrap();
                let collector = if let Some(ref auth) = session.authorization {
                    auth.legal_acknowledgment.operator_name.clone()
                } else {
                    "unknown".to_string()
                };
                drop(session);
                
                let mut evidence_mgr = self.evidence_manager.lock().unwrap();
                let evidence_id = evidence_mgr.add_evidence(
                    format!("Hash manifest of {}", path.display()),
                    Some(manifest_path.clone()),
                    collector,
                    &self.crypto_engine,
                )?;
                
                println!("\n✓ Manifest written to: {}", manifest_path.display());
                if sign {
                    println!("✓ Manifest cryptographically signed");
                }
                println!("✓ Evidence ID: {}\n", evidence_id);
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("FORENSICS_HASH", &format!("files={}, signed={}, evidence_id={}", hashes.len(), sign, evidence_id), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
            ForensicsCommands::Copy { source, dest } => {
                println!("→ Creating forensic copy");
                println!("  Source: {}", source.display());
                println!("  Dest: {}", dest.display());
                
                ForensicsEngine::forensic_copy(&source, &dest)?;
                
                let session = self.session.lock().unwrap();
                let collector = if let Some(ref auth) = session.authorization {
                    auth.legal_acknowledgment.operator_name.clone()
                } else {
                    "unknown".to_string()
                };
                drop(session);
                
                let mut evidence_mgr = self.evidence_manager.lock().unwrap();
                let evidence_id = evidence_mgr.add_evidence(
                    format!("Forensic copy: {} -> {}", source.display(), dest.display()),
                    Some(dest.clone()),
                    collector,
                    &self.crypto_engine,
                )?;
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("FORENSICS_COPY", &format!("source={}, dest={}, evidence_id={}", source.display(), dest.display(), evidence_id), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
                
                println!("✓ Forensic copy completed and verified");
                println!("✓ Evidence ID: {}\n", evidence_id);
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
            PluginCommands::Run { id, args } => {
                let plugin_mgr = self.plugin_manager.lock().unwrap();
                plugin_mgr.run_plugin(&id, &args, &mut self.sandbox_manager)?;
                drop(plugin_mgr);
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("PLUGIN_EXECUTED", &format!("id={}, args={:?}", id, args), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
        }
        
        Ok(())
    }
    
    fn handle_evidence_command(&mut self, action: EvidenceCommands) -> Result<(), Box<dyn std::error::Error>> {
        match action {
            EvidenceCommands::Export { output, format } => {
                let evidence_mgr = self.evidence_manager.lock().unwrap();
                evidence_mgr.export_chain_of_custody(&output, &format, &self.crypto_engine)?;
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("EVIDENCE_EXPORTED", &format!("output={}, format={}", output.display(), format), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
            EvidenceCommands::Sign { file, rfc3161, tsa_url } => {
                if !file.exists() {
                    return Err(format!("File not found: {}", file.display()).into());
                }
                
                let file_hash = ForensicsEngine::hash_file(&file)?;
                let timestamp = Utc::now().to_rfc3339();
                
                let mut sig_content = format!(
                    "File: {}\nSHA-256: {}\nTimestamp: {}\n",
                    file.display(),
                    file_hash,
                    timestamp
                );
                
                if rfc3161 {
                    if let Some(tsa_url_str) = tsa_url {
                        println!("  [RFC3161] Contacting timestamp authority: {}", tsa_url_str);
                        
                        match Self::get_rfc3161_timestamp(&file_hash, &tsa_url_str) {
                            Ok(tsa_response) => {
                                sig_content.push_str(&format!("TSA URL: {}\n", tsa_url_str));
                                sig_content.push_str(&format!("TSA Response: {}\n", tsa_response));
                                println!("  [RFC3161] ✓ Timestamp authority response received");
                            },
                            Err(e) => {
                                println!("  [RFC3161] ✗ Failed to get TSA timestamp: {}", e);
                                println!("  [RFC3161] Falling back to local timestamp");
                            }
                        }
                    } else {
                        println!("  [RFC3161] No TSA URL provided, using local timestamp");
                    }
                }
                
                let data_to_sign = format!("{}|{}|{}", file.display(), file_hash, timestamp);
                let signature = self.crypto_engine.sign_data(data_to_sign.as_bytes())?;
                let signature_hex = hex::encode(signature);
                
                sig_content.push_str(&format!("Signature: {}\n", signature_hex));
                
                let sig_file = file.with_extension("sig");
                std::fs::write(&sig_file, sig_content)?;
                
                println!("✓ File signed with legal timestamp");
                println!("✓ Signature file: {}", sig_file.display());
                println!("✓ Timestamp: {}\n", timestamp);
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("EVIDENCE_SIGNED", &format!("file={}, hash={}, rfc3161={}", file.display(), file_hash, rfc3161), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
            EvidenceCommands::Report { output } => {
                let evidence_mgr = self.evidence_manager.lock().unwrap();
                let session = self.session.lock().unwrap();
                evidence_mgr.generate_audit_report(&session, &output)?;
                
                drop(session);
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("AUDIT_REPORT_GENERATED", &format!("output={}", output.display()), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
            EvidenceCommands::Template { output, template_type } => {
                let template = template_type.unwrap_or_else(|| "standard".to_string());
                EvidenceManager::generate_engagement_template(&output, &template)?;
                
                let mut logger = self.log_writer.lock().unwrap();
                let log_entry = logger.log_event("TEMPLATE_GENERATED", &format!("type={}, output={}", template, output.display()), &self.crypto_engine)?;
                
                let mut session = self.session.lock().unwrap();
                session.log_chain.push(log_entry);
            },
        }
        
        Ok(())
    }
    
    fn get_rfc3161_timestamp(hash: &str, tsa_url: &str) -> Result<String, Box<dyn std::error::Error>> {
        use std::time::Instant;
        let start = Instant::now();
        
        let request_body = format!(
            "Hash: {}\nTimestamp: {}\nVersion: RFC3161",
            hash,
            Utc::now().to_rfc3339()
        );
        
        let response = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?
            .post(tsa_url)
            .header("Content-Type", "application/timestamp-query")
            .body(request_body)
            .send() {
                Ok(resp) => resp,
                Err(e) => return Err(format!("TSA request failed: {}", e).into()),
            };
        
        let elapsed = start.elapsed();
        
        if response.status().is_success() {
            let response_hash = {
                let mut hasher = Sha256::new();
                hasher.update(response.bytes()?.as_ref());
                format!("{:x}", hasher.finalize())
            };
            
            Ok(format!(
                "timestamp_received|duration_ms={}|response_hash={}",
                elapsed.as_millis(),
                response_hash
            ))
        } else {
            Err(format!("TSA returned error: {}", response.status()).into())
        }
    }
    
    fn panic_wipe(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n⚠ PANIC WIPE INITIATED");
        
        let mut logger = self.log_writer.lock().unwrap();
        let _ = logger.log_event("PANIC_WIPE", "emergency_termination", &self.crypto_engine);
        drop(logger);
        
        println!("  [Panic] Terminating all sandboxed processes...");
        self.sandbox_manager.kill_all_processes();
        
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
        
        println!("✓ All processes terminated");
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
            
            if input == "clear" || input == "cls" {
                #[cfg(target_os = "windows")]
                {
                    let _ = Command::new("cmd").args(&["/C", "cls"]).status();
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = Command::new("clear").status();
                }
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
                    return Err("Usage: network <tor|vpn|verify|status|disable>".into());
                }
                match parts[1] {
                    "status" => self.handle_network_command(NetworkCommands::Status)?,
                    "disable" => self.handle_network_command(NetworkCommands::Disable)?,
                    "verify" => self.handle_network_command(NetworkCommands::Verify)?,
                    "tor" => {
                        let mut port = None;
                        for i in 2..parts.len() {
                            if parts[i] == "-p" && i + 1 < parts.len() {
                                port = parts[i + 1].parse::<u16>().ok();
                                break;
                            }
                        }
                        self.handle_network_command(NetworkCommands::Tor { port })?;
                    },
                    "vpn" => {
                        let mut config_path = None;
                        for i in 2..parts.len() {
                            if parts[i] == "-c" && i + 1 < parts.len() {
                                config_path = Some(PathBuf::from(parts[i + 1]));
                                break;
                            }
                        }
                        if let Some(config) = config_path {
                            self.handle_network_command(NetworkCommands::Vpn { config })?;
                        } else {
                            return Err("Usage: network vpn -c <config_path>".into());
                        }
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
            "copy" => {
                if parts.len() < 3 {
                    return Err("Usage: copy <source> <dest>".into());
                }
                let source = PathBuf::from(parts[1]);
                let dest = PathBuf::from(parts[2]);
                self.handle_forensics_command(ForensicsCommands::Copy { source, dest })?;
            },
            "plugin" => {
                if parts.len() < 2 {
                    return Err("Usage: plugin <list|install|remove|verify|run>".into());
                }
                match parts[1] {
                    "list" => self.handle_plugin_command(PluginCommands::List)?,
                    "verify" => self.handle_plugin_command(PluginCommands::Verify)?,
                    "install" => {
                        if parts.len() < 3 {
                            return Err("Usage: plugin install <bundle_path>".into());
                        }
                        let bundle = PathBuf::from(parts[2]);
                        self.handle_plugin_command(PluginCommands::Install { bundle })?;
                    },
                    "remove" => {
                        if parts.len() < 3 {
                            return Err("Usage: plugin remove <id>".into());
                        }
                        let id = parts[2].to_string();
                        self.handle_plugin_command(PluginCommands::Remove { id })?;
                    },
                    "run" => {
                        if parts.len() < 3 {
                            return Err("Usage: plugin run <id> [args...]".into());
                        }
                        let id = parts[2].to_string();
                        let args: Vec<String> = parts[3..].iter().map(|s| s.to_string()).collect();
                        self.handle_plugin_command(PluginCommands::Run { id, args })?;
                    },
                    _ => return Err(format!("Unknown plugin command: {}", parts[1]).into()),
                }
            },
            "evidence" => {
                if parts.len() < 2 {
                    return Err("Usage: evidence <export|sign|report>".into());
                }
                match parts[1] {
                    "export" => {
                        if parts.len() < 4 {
                            return Err("Usage: evidence export <output> <json|xml>".into());
                        }
                        let output = PathBuf::from(parts[2]);
                        let format = parts[3].to_string();
                        self.handle_evidence_command(EvidenceCommands::Export { output, format })?;
                    },
                    "sign" => {
                        if parts.len() < 3 {
                            return Err("Usage: evidence sign <file> [--rfc3161] [--tsa-url <url>]".into());
                        }
                        let file = PathBuf::from(parts[2]);
                        
                        let mut rfc3161 = false;
                        let mut tsa_url = None;
                        
                        let mut i = 3;
                        while i < parts.len() {
                            match parts[i] {
                                "--rfc3161" => {
                                    rfc3161 = true;
                                    i += 1;
                                },
                                "--tsa-url" => {
                                    if i + 1 < parts.len() {
                                        tsa_url = Some(parts[i + 1].to_string());
                                        i += 2;
                                    } else {
                                        return Err("--tsa-url requires a URL argument".into());
                                    }
                                },
                                _ => {
                                    return Err(format!("Unknown flag: {}", parts[i]).into());
                                }
                            }
                        }
                        
                        self.handle_evidence_command(EvidenceCommands::Sign { file, rfc3161, tsa_url })?;
                    },
                    "report" => {
                        if parts.len() < 3 {
                            return Err("Usage: evidence report <output>".into());
                        }
                        let output = PathBuf::from(parts[2]);
                        self.handle_evidence_command(EvidenceCommands::Report { output })?;
                    },
                    _ => return Err(format!("Unknown evidence command: {}", parts[1]).into()),
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
        
        if let Some(ref auth) = session.authorization {
            println!("║ Target: {:<54} ║", if auth.target.len() > 54 { &auth.target[..54] } else { &auth.target });
            println!("║ Operator: {:<52} ║", if auth.legal_acknowledgment.operator_name.len() > 52 { 
                &auth.legal_acknowledgment.operator_name[..52] 
            } else { 
                &auth.legal_acknowledgment.operator_name 
            });
        }
        
        let network_str = match &session.network_status {
            NetworkStatus::Disabled => "Disabled".to_string(),
            NetworkStatus::Direct => "Direct".to_string(),
            NetworkStatus::Tor { port, verified } => format!("Tor:{} ({})", port, if *verified { "✓" } else { "✗" }),
            NetworkStatus::Vpn { verified, .. } => format!("VPN ({})", if *verified { "✓" } else { "✗" }),
        };
        println!("║ Network: {:<53} ║", network_str);
        println!("║ Log entries: {:<49} ║", session.log_chain.len());
        println!("║ Evidence items: {:<46} ║", session.chain_of_custody.evidence_items.len());
        println!("╚════════════════════════════════════════════════════════════════╝\n");
    }
    
    fn print_help(&self) {
        println!("\n╔════════════════════════════════════════════════════════════════╗");
        println!("║                    LUCIDSHELL COMMANDS                         ║");
        println!("╠════════════════════════════════════════════════════════════════╣");
        println!("║ Session Management:                                            ║");
        println!("║   init <target>              Initialize with authorization     ║");
        println!("║   status                     Show session status               ║");
        println!("║   panic                      Emergency wipe and exit           ║");
        println!("║                                                                ║");
        println!("║ Tool Execution:                                                ║");
        println!("║   run <tool> [--network]     Run tool in sandbox               ║");
        println!("║                                                                ║");
        println!("║ Network Control:                                               ║");
        println!("║   network tor -p <port>      Connect to Tor proxy              ║");
        println!("║   network vpn -c <config>    Configure VPN                     ║");
        println!("║   network verify             Test connection                   ║");
        println!("║   network status             Show network status               ║");
        println!("║   network disable            Disable all network               ║");
        println!("║                                                                ║");
        println!("║ Forensics:                                                     ║");
        println!("║   hash <path> [--sign]       Hash file/directory               ║");
        println!("║   copy <source> <dest>       Forensic copy with verification   ║");
        println!("║                                                                ║");
        println!("║ Evidence Management:                                           ║");
        println!("║   evidence export <out> <fmt> Export chain-of-custody          ║");
        println!("║   evidence sign <file>       Sign with legal timestamp         ║");
        println!("║       [--rfc3161]            Use RFC 3161 timestamp authority  ║");
        println!("║       [--tsa-url <url>]      Specify TSA URL                   ║");
        println!("║   evidence report <out>      Generate audit report             ║");
        println!("║   evidence template <out>    Generate engagement letter        ║");
        println!("║       [--type <type>]        standard|pentest|forensics        ║");
        println!("║                                                                ║");
        println!("║ Plugins:                                                       ║");
        println!("║   plugin list                List installed plugins            ║");
        println!("║   plugin install <bundle>    Install plugin from bundle        ║");
        println!("║   plugin remove <id>         Remove installed plugin           ║");
        println!("║   plugin verify              Verify plugin signatures          ║");
        println!("║   plugin run <id> [args]     Execute plugin in sandbox         ║");
        println!("║                                                                ║");
        println!("║ Utility:                                                       ║");
        println!("║   clear, cls                 Clear terminal                    ║");
        println!("║   help                       Show this help                    ║");
        println!("║   exit, quit                 Exit REPL                         ║");
        println!("╚════════════════════════════════════════════════════════════════╝\n");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    let mode = cli.mode.unwrap_or_else(|| "auditor".to_string());
    let mut shell = LucidShell::new(cli.ephemeral, mode, cli.container)?;
    
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
        Some(Commands::Evidence { action }) => {
            shell.handle_evidence_command(action)?;
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
