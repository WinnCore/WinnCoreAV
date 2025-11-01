## Description

<!-- Brief summary of changes -->

## Type of Change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Documentation update
- [ ] CI/tooling change

## AI Assistance Disclosure

**Required for all PRs. See [COMPLIANCE.md](../COMPLIANCE.md).**

- [ ] AI assistance used in this PR
- [ ] If yes, provider(s): <!-- e.g., Claude 3.5 Sonnet, GitHub Copilot -->
- [ ] If yes, prompt source:
  - [ ] Public (provide URL): ___________
  - [ ] Confidential (not published)
- [ ] Human authorship summary: <!-- e.g., "AI generated scaffold, I rewrote logic and error handling" -->

## Third-Party Code

- [ ] This PR includes third-party code or dependencies
- [ ] If yes, license compatibility verified (MIT-compatible)
- [ ] If yes, attribution added to NOTICE file

## Testing

- [ ] Local tests pass (`cargo test`)
- [ ] CI checks pass (wait for Actions)
- [ ] EICAR integration test passes (if applicable)
- [ ] Ran `tools/scan_repo.sh` locally (exit code 0)

## Compliance

- [ ] No secrets committed (checked with gitleaks or detect-secrets)
- [ ] No raw EICAR string or GPL banners added
- [ ] ARM64-only changes (no x86/x86_64 code paths)
- [ ] Follows [CONTRIBUTING.md](../CONTRIBUTING.md) guidelines

## Checklist

- [ ] Code follows project style (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Documentation updated (if needed)
