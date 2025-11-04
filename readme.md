# LucidShell - White-Hat Security Shell

## Implementation Plan

### Phase 1: Core Shell & Sandboxing
1. Rust REPL with command parser (clap-based)
2. AppContainer + Job Objects wrapper for child processes
3. Windows CNG integration for crypto primitives
4. Ephemeral memory-mapped storage (PAGE_READWRITE | SEC_COMMIT with encryption)

### Phase 2: Authorization & Legal Framework
1. Rules of Engagement consent system with cryptographic signatures
2. Evidence chain-of-custody metadata collection
3. Engagement letter templates and audit trail storage

### Phase 3: Network Controls & Anonymity
1. WFP (Windows Filtering Platform) firewall integration per tool
2. SOCKS5/Tor routing with kill-switch on anonymization failure
3. WireGuard/OpenVPN management via system drivers

### Phase 4: Tooling & Plugin System
1. Sandboxed tool execution framework with capability declarations
2. Plugin API with signature verification (Authenticode)
3. Curated tool set: network scanners, forensic parsers, passive collectors

### Phase 5: Forensics & Evidence Capture
1. VSS-based read-only mounts and forensic copy APIs
2. SHA-256/SHA-3 hashing with signed manifests
3. Tamper-evident log chains (HMAC with append-only storage)

### Phase 6: Hardware Integration & Updates
1. FIDO2/YubiKey support for auth and container unlocking
2. Signed update mechanism with reproducible build verification
3. Panic wipe for emergency session termination

---

## Cargo.toml Dependencies
```
[dependencies]
clap = { version = "4.5", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.10", features = ["v4", "serde"] }
hex = "0.4"
winapi = { version = "0.3", features = ["jobapi2", "winnt", "securitybaseapi"] }
ring = "0.17"  # For cryptographic operations
```
