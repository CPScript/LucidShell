> NOTE; This is still a work in progress!

## **How to Use:**

### **Build(compile) the Plugin:**
```bash
# Compile the plugin

cd plugins\devtools\

rustc -o devtools.exe src/main.rs
```

### **Install/UnInstall in LucidShell:**
```bash
# Install
lucidshell> plugin install devtools.exe

# UnInstall
lucidshell> plugin remove devtools
```

### **Use the Plugin:**
```bash
# List available tools
lucidshell> plugin run devtools list

# Get help for a specific tool
lucidshell> plugin run devtools help git

# Run git commands
lucidshell> plugin run devtools run git status
lucidshell> plugin run devtools run git clone https://github.com/user/repo

# Use Python
lucidshell> plugin run devtools run python -c "print('Hello')"
lucidshell> plugin run devtools run pip install requests

# Use curl for API testing
lucidshell> plugin run devtools run curl -X GET https://api.github.com

# Export manifest for verification
lucidshell> plugin run devtools manifest devtools.json
```
