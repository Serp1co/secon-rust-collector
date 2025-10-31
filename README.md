# SELinux Rust Manager

A simple, focused Rust library for managing SELinux and eBPF programs over SSH.

## Features

- **SSH Connection Management** - Connect to remote hosts via SSH (password or key auth)
- **SELinux Operations** - Check status, manage booleans, view denials, handle contexts
- **eBPF Support** - Load/unload eBPF programs for kernel-level monitoring

## Project Structure

```
src/
├── lib.rs      # Library exports
├── main.rs     # Simple demo
├── ssh.rs      # SSH connection management
├── selinux.rs  # SELinux commands
└── ebpf.rs     # eBPF program management
```

## Usage

### Basic Connection

```rust
use selinux_rust_manager::ssh::SshManager;

// Create SSH manager
let manager = SshManager::new();

// Connect with password
let session = manager.connect("192.168.1.100", 22, "root", "password").await?;

// Or connect with SSH key
let session = manager.connect_with_key(
    "192.168.1.100",
    22,
    "root",
    &private_key_content,
    None  // passphrase
).await?;
```

### SELinux Operations

```rust
use selinux_rust_manager::selinux;

// Get SELinux status
let status = selinux::get_status(&session).await?;

// Get booleans
let booleans = selinux::get_booleans(&session).await?;

// Set a boolean
selinux::set_boolean(&session, "httpd_can_network_connect", true).await?;

// Get recent AVC denials
let denials = selinux::get_recent_denials(&session, 60).await?;

// Get file context
let context = selinux::get_context(&session, "/etc/passwd").await?;

// Restore contexts
selinux::restore_context(&session, "/var/www", true).await?;
```

### eBPF Operations

```rust
use selinux_rust_manager::ebpf;

// Check eBPF support
let supported = ebpf::check_support(&session).await?;

// Load AVC monitor
let program = ebpf::load_avc_monitor(&session).await?;

// List programs
let programs = ebpf::list_programs(&session).await?;

// Unload program
ebpf::unload_program(&session, &program.id).await?;
```

## Running Examples

```bash
# Run the main demo
cargo run

# Run the detailed example
cargo run --example basic_usage
```

## Requirements

### On Your Machine
- Rust 1.70+
- SSH client

### On Target Hosts
- SSH server
- SELinux (for SELinux operations)
- Kernel 4.x+ (for eBPF)
- Optional: bpftool, clang (for eBPF compilation)

## Building

```bash
# Build the library
cargo build

# Run tests
cargo test

# Build for release
cargo build --release
```

## Next Steps

This is a minimal foundation. You can extend it by:

1. **Connection Pooling** - Reuse SSH connections
2. **More SELinux Commands** - Add policy management, module loading, etc.
3. **Advanced eBPF** - More program types, event reading, etc.
4. **Error Recovery** - Retry logic, better error handling
5. **Configuration** - Add config file support
6. **REST/gRPC API** - Add API layer on top

## License

MIT