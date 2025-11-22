use av_core::logging::log_non_elf_skip_should_emit;

#[test]
fn non_elf_skip_throttling() {
    // First call should emit
    assert!(log_non_elf_skip_should_emit(false));
    // Subsequent calls should be suppressed until 500th
    for _ in 0..498 {
        assert!(!log_non_elf_skip_should_emit(false));
    }
    // 500th (count = 500) should emit
    assert!(log_non_elf_skip_should_emit(false));
    // Verbose mode always emits
    assert!(log_non_elf_skip_should_emit(true));
}
