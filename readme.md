# LucidShell - White-Hat Security Shell (not optimized)

### About; 
> This is a **sophisticated white-hat security framework** with exceptional attention to legal compliance and evidence handling. The cryptographic logging, chain-of-custody, and engagement letter system make it suitable for professional security work where legal defensibility matters. This is ment for Windows-based security operations.

Y/N | Use Cases
---|---
✅ | Penetration testing engagements
✅ | Digital forensics investigations
✅ | Security auditing with legal compliance
✅ | Red team operations with documentation
✅ | Incident response with evidence handling
⚠️ | Production use (requires encrypted container. soon)
❌ | Multi-platform operations (MADE FOR WINDOWS)


# Command Reference & Analysis

### **Session Management**
- `init <target> [--engagement-letter <path>]` - Initialize session with authorization
- `status` - Display current session status
- `panic` - Emergency wipe: terminate processes, clear memory, exit
- `repl` - Enter interactive REPL mode
- `exit` / `quit` - Exit REPL mode
- `clear` / `cls` - Clear terminal screen

### **Tool Execution**
- `run <tool> [--network] [--profile <minimal|standard|elevated>] [args...]` - Execute tool in sandbox
  - Profiles control filesystem/registry access levels
  - `--network` flag enables network (requires verification)
  - Built-in tools: `ping`, `ipconfig`, `netstat`, `nslookup`, `tracert`, `whoami`, `systeminfo`

### **Network Control**
- `network tor [-p <port>]` - Connect via Tor SOCKS5 proxy (default port 9050)
  - Verifies connection via check.torproject.org
  - Enables kill-switch on verification failure
- `network vpn -c <config>` - Configure VPN connection
- `network verify` - Test and verify active connection
- `network status` - Show detailed network status
- `network disable` - Disable all network access

### **Forensics Operations**
- `forensics mount <target> [--vss]` - Mount target for forensic analysis (read-only)
  - `--vss` enables Volume Shadow Copy snapshot
- `forensics hash <path> [--sign]` - Compute SHA-256 hashes
  - Works on files or entire directories
  - `--sign` cryptographically signs the manifest
- `forensics copy <source> <dest>` - Forensic copy with hash verification
  - Verifies integrity before and after copy
  - Automatic evidence logging

### **Evidence Management**
- `evidence export <output> --format <json|xml>` - Export chain-of-custody
  - Includes cryptographic signatures
  - Full audit trail with timestamps
- `evidence sign <file> [--rfc3161] [--tsa-url <url>]` - Sign file with legal timestamp
  - `--rfc3161` enables RFC 3161 timestamp authority
  - `--tsa-url` specifies TSA endpoint (e.g., http://timestamp.digicert.com)
- `evidence report <output>` - Generate comprehensive audit report
  - Session details, authorization, full log chain
  - Chain-of-custody documentation
  - Evidence items and custody log
- `evidence template <output> [--template-type <standard|pentest|forensics>]` - Generate engagement letter template
  - **standard**: General security testing
  - **pentest**: Penetration testing engagement
  - **forensics**: Digital forensics investigation

### **Plugin System**
- `plugin list` - List all installed plugins
- `plugin install <bundle>` - Install plugin from bundle path
  - Verifies and signs plugin on installation
  - Records capabilities (network, filesystem, registry)
- `plugin remove <id>` - Uninstall plugin by ID
- `plugin verify` - Verify signatures of all installed plugins
- `plugin run <id> [args...]` - Execute plugin in sandbox
  - Respects plugin capability restrictions
  - Full logging and evidence collection

### **Hidden/Undocumented Features**
- **Session modes** (CLI flag): `--mode <auditor|forensics|developer|minimal>` - Affects default behavior
- **Ephemeral mode** (CLI flag): `--ephemeral` - Memory-only, no disk writes
- **Container support** (CLI flag): `--container <path>` - Encrypted persistent storage with security audit
- **Job object isolation** (Windows): Automatic process containment with kill-on-close
- **WFP firewall integration** (Windows): Per-process network blocking via Windows Filtering Platform
- **Secure memory wiping**: All sensitive data zeroed on drop using volatile writes
- **Hash chain logging**: Every log entry chained with previous hash for tamper detection
- **Automatic evidence collection**: Tool executions auto-generate evidence items

---

## Implementation Plan

* **Sandbox Isolation** - Job Objects work, but is not enforcing filesystem/registry restrictions at the Windows API level.
* **RFC 3161** - Currently sends HTTP requests but doesn't actually parse RFC 3161 ASN.1 responses. A real TSA would reject requests when using this shell. It's a good *stub* though, and i plan on fixing such soon
* **Container Encryption** - Verifys the container exists and has correct permissions, but doesn't actually decrypt or use it. *It's just a file check*.
* **Plugin Execution** - Install/verify works, but no actual sandboxed execution or API.

All of these will be fixed/completed soon.
