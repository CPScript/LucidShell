# LucidShell - White-Hat Security Shell

## Implementation Plan

* **WFP Firewall** - Declare it but isn't implemented. The network "security" is just status tracking, not actual OS-level blocking.
* **Sandbox Isolation** - Job Objects work, but is not enforcing filesystem/registry restrictions at the Windows API level.
* **RFC 3161** - Currently sends HTTP requests but doesn't actually parse RFC 3161 ASN.1 responses. A real TSA would reject your requests when using this shell. It's a good *stub* though, and i plan on fixing such soon
* **Container Encryption** - Verifys the container exists and has correct permissions, but doesn't actually decrypt or use it. *It's just a file check*.
* **Plugin Execution** - Install/verify works, but no actual sandboxed execution or API.

All of these will be fixed/completed soon.
