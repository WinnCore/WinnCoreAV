# av-stack-trace

Stack trace validation helpers for WinnCoreAV to help detect direct syscalls and inline syscall abuse. Uses process maps information to validate return addresses.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_stack_trace::SyscallValidator;

fn main() {
    let _validator = SyscallValidator::new();
}
```

## License

Apache-2.0

