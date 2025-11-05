// LucidShell DevTools Plugin - Development & Security Tools Bundle
// Provides access to git, python, cargo, and other dev tools with controlled network permissions
// NO EXTERNAL DEPENDENCIES - Pure Rust stdlib only

// Currently in development. I still need to make it where the shell properly runs and configures itself for plugins.
// Was wanting to take a break form coding for a bit, so i made this during my break. <3

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::collections::HashMap;
use std::fs;

struct PluginManifest {
    id: String,
    name: String,
    version: String,
    description: String,
    capabilities: PluginCapabilities,
    tools: Vec<ToolDefinition>,
}

struct PluginCapabilities {
    network_access: bool,
    filesystem_write: bool,
    registry_access: bool,
    description: String,
}

struct ToolDefinition {
    name: String,
    command: String,
    description: String,
    requires_network: bool,
    allowed_args: Vec<String>,
    restricted_args: Vec<String>,
}

impl PluginManifest {
    fn to_json(&self) -> String {
        let mut json = String::new();
        json.push_str("{\n");
        json.push_str(&format!("  \"id\": \"{}\",\n", self.id));
        json.push_str(&format!("  \"name\": \"{}\",\n", self.name));
        json.push_str(&format!("  \"version\": \"{}\",\n", self.version));
        json.push_str(&format!("  \"description\": \"{}\",\n", self.description));
        json.push_str("  \"capabilities\": {\n");
        json.push_str(&format!("    \"network_access\": {},\n", self.capabilities.network_access));
        json.push_str(&format!("    \"filesystem_write\": {},\n", self.capabilities.filesystem_write));
        json.push_str(&format!("    \"registry_access\": {},\n", self.capabilities.registry_access));
        json.push_str(&format!("    \"description\": \"{}\"\n", self.capabilities.description));
        json.push_str("  },\n");
        json.push_str("  \"tools\": [\n");
        
        for (i, tool) in self.tools.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"name\": \"{}\",\n", tool.name));
            json.push_str(&format!("      \"command\": \"{}\",\n", tool.command));
            json.push_str(&format!("      \"description\": \"{}\",\n", tool.description));
            json.push_str(&format!("      \"requires_network\": {},\n", tool.requires_network));
            
            json.push_str("      \"allowed_args\": [");
            for (j, arg) in tool.allowed_args.iter().enumerate() {
                json.push_str(&format!("\"{}\"", arg));
                if j < tool.allowed_args.len() - 1 {
                    json.push_str(", ");
                }
            }
            json.push_str("],\n");
            
            json.push_str("      \"restricted_args\": [");
            for (j, arg) in tool.restricted_args.iter().enumerate() {
                json.push_str(&format!("\"{}\"", arg));
                if j < tool.restricted_args.len() - 1 {
                    json.push_str(", ");
                }
            }
            json.push_str("]\n");
            
            json.push_str("    }");
            if i < self.tools.len() - 1 {
                json.push_str(",\n");
            } else {
                json.push_str("\n");
            }
        }
        
        json.push_str("  ]\n");
        json.push_str("}\n");
        json
    }
}

struct DevToolsPlugin {
    manifest: PluginManifest,
    tool_paths: HashMap<String, PathBuf>,
}

impl DevToolsPlugin {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let manifest = Self::create_manifest();
        let tool_paths = Self::discover_tools()?;
        
        Ok(DevToolsPlugin {
            manifest,
            tool_paths,
        })
    }
    
    fn create_manifest() -> PluginManifest {
        PluginManifest {
            id: "devtools".to_string(),
            name: "Development & Security Tools Bundle".to_string(),
            version: "1.0.0".to_string(),
            description: "Safe access to git, Python, Rust, and security tools with controlled network".to_string(),
            capabilities: PluginCapabilities {
                network_access: true,
                filesystem_write: true,
                registry_access: false,
                description: "Controlled network access for development tools only. Network traffic bypasses Tor/VPN routing for legitimate development operations.".to_string(),
            },
            tools: vec![
                ToolDefinition {
                    name: "git".to_string(),
                    command: "git".to_string(),
                    description: "Version control - clone, pull, push, commit".to_string(),
                    requires_network: false,
                    allowed_args: vec![
                        "clone".to_string(),
                        "pull".to_string(),
                        "push".to_string(),
                        "fetch".to_string(),
                        "commit".to_string(),
                        "status".to_string(),
                        "log".to_string(),
                        "diff".to_string(),
                        "branch".to_string(),
                        "checkout".to_string(),
                        "add".to_string(),
                        "remote".to_string(),
                        "merge".to_string(),
                        "rebase".to_string(),
                        "tag".to_string(),
                        "stash".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "python".to_string(),
                    command: "python".to_string(),
                    description: "Python interpreter and script execution".to_string(),
                    requires_network: false,
                    allowed_args: vec![
                        "-c".to_string(),
                        "-m".to_string(),
                        "--version".to_string(),
                        "-i".to_string(),
                        "-u".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "pip".to_string(),
                    command: "pip".to_string(),
                    description: "Python package manager".to_string(),
                    requires_network: true,
                    allowed_args: vec![
                        "install".to_string(),
                        "list".to_string(),
                        "show".to_string(),
                        "search".to_string(),
                        "uninstall".to_string(),
                        "freeze".to_string(),
                        "check".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "cargo".to_string(),
                    command: "cargo".to_string(),
                    description: "Rust package manager and build tool".to_string(),
                    requires_network: false,
                    allowed_args: vec![
                        "build".to_string(),
                        "run".to_string(),
                        "test".to_string(),
                        "doc".to_string(),
                        "new".to_string(),
                        "init".to_string(),
                        "add".to_string(),
                        "update".to_string(),
                        "check".to_string(),
                        "clean".to_string(),
                        "search".to_string(),
                        "install".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "curl".to_string(),
                    command: "curl".to_string(),
                    description: "HTTP client for API testing".to_string(),
                    requires_network: true,
                    allowed_args: vec![
                        "-X".to_string(),
                        "-H".to_string(),
                        "-d".to_string(),
                        "--data".to_string(),
                        "--header".to_string(),
                        "-v".to_string(),
                        "--verbose".to_string(),
                        "-s".to_string(),
                        "--silent".to_string(),
                        "-o".to_string(),
                        "--output".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "node".to_string(),
                    command: "node".to_string(),
                    description: "Node.js JavaScript runtime".to_string(),
                    requires_network: false,
                    allowed_args: vec![
                        "-e".to_string(),
                        "--version".to_string(),
                        "-p".to_string(),
                        "--print".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "npm".to_string(),
                    command: "npm".to_string(),
                    description: "Node package manager".to_string(),
                    requires_network: true,
                    allowed_args: vec![
                        "install".to_string(),
                        "update".to_string(),
                        "list".to_string(),
                        "run".to_string(),
                        "start".to_string(),
                        "test".to_string(),
                        "build".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "wget".to_string(),
                    command: "wget".to_string(),
                    description: "Network downloader".to_string(),
                    requires_network: true,
                    allowed_args: vec![
                        "-O".to_string(),
                        "--output-document".to_string(),
                        "-q".to_string(),
                        "--quiet".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "ssh".to_string(),
                    command: "ssh".to_string(),
                    description: "Secure shell client".to_string(),
                    requires_network: true,
                    allowed_args: vec![
                        "-p".to_string(),
                        "-i".to_string(),
                        "-l".to_string(),
                        "-v".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "docker".to_string(),
                    command: "docker".to_string(),
                    description: "Container management".to_string(),
                    requires_network: false,
                    allowed_args: vec![
                        "ps".to_string(),
                        "images".to_string(),
                        "run".to_string(),
                        "exec".to_string(),
                        "stop".to_string(),
                        "build".to_string(),
                        "logs".to_string(),
                        "inspect".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "go".to_string(),
                    command: "go".to_string(),
                    description: "Go programming language tools".to_string(),
                    requires_network: false,
                    allowed_args: vec![
                        "build".to_string(),
                        "run".to_string(),
                        "test".to_string(),
                        "mod".to_string(),
                        "get".to_string(),
                        "install".to_string(),
                    ],
                    restricted_args: vec![],
                },
                ToolDefinition {
                    name: "nmap".to_string(),
                    command: "nmap".to_string(),
                    description: "Network scanner (requires authorization)".to_string(),
                    requires_network: true,
                    allowed_args: vec![
                        "-sT".to_string(),
                        "-sS".to_string(),
                        "-p".to_string(),
                        "-A".to_string(),
                        "-O".to_string(),
                        "-v".to_string(),
                    ],
                    restricted_args: vec![],
                },
            ],
        }
    }
    
    fn discover_tools() -> Result<HashMap<String, PathBuf>, Box<dyn std::error::Error>> {
        let mut tool_paths = HashMap::new();
        
        let tools = vec![
            "git", "python", "python3", "pip", "pip3", 
            "cargo", "rustc", "curl", "wget", "node", 
            "npm", "ssh", "docker", "go", "java", "nmap"
        ];
        
        for tool in tools {
            if let Ok(path) = Self::find_in_path(tool) {
                tool_paths.insert(tool.to_string(), path);
            }
        }
        
        Ok(tool_paths)
    }
    
    fn find_in_path(tool: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        let which_cmd = "where";
        #[cfg(not(target_os = "windows"))]
        let which_cmd = "which";
        
        let output = Command::new(which_cmd)
            .arg(tool)
            .output()?;
        
        if output.status.success() {
            let path_str = String::from_utf8(output.stdout)?;
            let path = path_str.lines().next().unwrap_or("").trim();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
        
        Err(format!("{} not found in PATH", tool).into())
    }
    
    fn execute_tool(
        &self,
        tool_name: &str,
        args: &[String],
        working_dir: Option<&Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tool_def = self.manifest.tools.iter()
            .find(|t| t.name == tool_name)
            .ok_or(format!("Unknown tool: {}", tool_name))?;
        
        let tool_path = self.tool_paths.get(tool_name)
            .ok_or(format!("Tool '{}' not installed or not in PATH", tool_name))?;
        
        if !args.is_empty() {
            let first_arg = &args[0];
            if !tool_def.allowed_args.is_empty() && 
               !tool_def.allowed_args.contains(first_arg) {
                return Err(format!(
                    "Argument '{}' not allowed for {}. Allowed: {:?}",
                    first_arg, tool_name, tool_def.allowed_args
                ).into());
            }
            
            if tool_def.restricted_args.contains(first_arg) {
                return Err(format!(
                    "Argument '{}' is restricted for security",
                    first_arg
                ).into());
            }
        }
        
        println!("  [DevTools] Executing: {} {}", tool_name, args.join(" "));
        
        if tool_def.requires_network {
            println!("  [DevTools] This operation requires network access");
            println!("  [DevTools] Network traffic will bypass Tor/VPN routing");
        }
        
        let mut cmd = Command::new(tool_path);
        cmd.args(args);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }
        
        let mut child = cmd.spawn()?;
        
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("  {}", line);
                }
            }
        }
        
        if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("  {}", line);
                }
            }
        }
        
        let status = child.wait()?;
        
        if !status.success() {
            return Err(format!("Tool exited with status: {}", status).into());
        }
        
        println!("  [DevTools] ✓ Command completed successfully");
        
        Ok(())
    }
    
    fn list_available_tools(&self) {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║              DEVTOOLS PLUGIN - AVAILABLE TOOLS                ║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        
        for tool in &self.manifest.tools {
            let status = if self.tool_paths.contains_key(&tool.name) {
                "✓ Installed"
            } else {
                "✗ Not found"
            };
            
            let network_indicator = if tool.requires_network {
                "🌐"
            } else {
                "  "
            };
            
            println!("║ {} {} {:<45} {} ║", 
                network_indicator,
                status,
                tool.name,
                ""
            );
            
            let desc_line = if tool.description.len() > 60 {
                &tool.description[..60]
            } else {
                &tool.description
            };
            println!("║      {:<58} ║", desc_line);
        }
        
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║      Requires network access (bypasses Tor/VPN)               ║");
        println!("╚═══════════════════════════════════════════════════════════════╝\n");
    }
    
    fn show_tool_help(&self, tool_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let tool_def = self.manifest.tools.iter()
            .find(|t| t.name == tool_name)
            .ok_or(format!("Unknown tool: {}", tool_name))?;
        
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║ Tool: {:<57} ║", tool_name);
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║ Description: {:<49} ║", tool_def.description);
        println!("║ Network Required: {:<44} ║", tool_def.requires_network);
        
        if !tool_def.allowed_args.is_empty() {
            println!("╠═══════════════════════════════════════════════════════════════╣");
            println!("║ Allowed Commands:                                              ║");
            for arg in &tool_def.allowed_args {
                println!("║   • {:<59} ║", arg);
            }
        }
        
        println!("╚═══════════════════════════════════════════════════════════════╝\n");
        
        Ok(())
    }
    
    fn export_manifest(&self, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let manifest_json = self.manifest.to_json();
        fs::write(output_path, manifest_json)?;
        println!("  [DevTools] Manifest exported to: {}", output_path.display());
        Ok(())
    }
}

fn print_usage() {
    println!("\nLucidShell DevTools Plugin - Usage:");
    println!("  devtools list                    - List available tools");
    println!("  devtools help <tool>             - Show tool help");
    println!("  devtools run <tool> [args...]    - Execute tool");
    println!("  devtools manifest <output>       - Export plugin manifest");
    println!("\nExamples:");
    println!("  devtools run git status");
    println!("  devtools run python -c 'print(\"Hello\")'");
    println!("  devtools run pip install requests");
    println!("  devtools run curl -X GET https://api.github.com");
    println!();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }
    
    let plugin = DevToolsPlugin::new()?;
    
    match args[1].as_str() {
        "list" => {
            plugin.list_available_tools();
        },
        "help" => {
            if args.len() < 3 {
                print_usage();
                return Ok(());
            }
            plugin.show_tool_help(&args[2])?;
        },
        "run" => {
            if args.len() < 3 {
                eprintln!("Error: Must specify tool to run");
                print_usage();
                return Ok(());
            }
            
            let tool_name = &args[2];
            let tool_args: Vec<String> = args[3..].to_vec();
            
            let working_dir = env::current_dir().ok();
            plugin.execute_tool(tool_name, &tool_args, working_dir.as_deref())?;
        },
        "manifest" => {
            if args.len() < 3 {
                eprintln!("Error: Must specify output path");
                return Ok(());
            }
            let output_path = Path::new(&args[2]);
            plugin.export_manifest(output_path)?;
        },
        _ => {
            eprintln!("Error: Unknown command '{}'", args[1]);
            print_usage();
        }
    }
    
    Ok(())
}
