# Contributing to WinnCoreAV

Thank you for your interest in contributing!

## Developer Certificate of Origin (DCO)

By submitting a pull request, you certify:

1. **Rights to Contribute:** You have the legal right to submit the code under the project's MIT license.

2. **AI-Assisted Code Disclosure:** If you used AI tools (e.g., GitHub Copilot, Claude, GPT-4):
   - Disclose provider and model in PR template
   - Confirm you own rights to AI-generated output per provider ToS
   - Provide prompt source (public URL or "confidential")
   - Summarize human authorship percentage

3. **Third-Party Code:** No proprietary, confidential, or incompatibly-licensed code included without explicit approval.

4. **Indemnification:** You indemnify maintainers against claims arising from your contributions, including AI-generated content.

5. **Compliance with Laws:** Your contribution complies with export controls, sanctions, and local IP laws.

## Sign-off

Add `Signed-off-by: Your Name <your.email@example.com>` to commit messages:
```bash
git commit -s -m "feat: add feature"
```

Or configure globally:
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## AI Provenance Example
```
feat(core): add entropy-based heuristic scoring

AI-Assisted: Claude 3.5 Sonnet
Prompt: Public (https://example.com/prompts/heuristics.md)
Human-Edit: 70% new logic, 30% AI scaffold
No third-party code included

Signed-off-by: Jane Doe <jane@example.com>
```

See [COMPLIANCE.md](COMPLIANCE.md) for full policy.

## Code Style

- Run `cargo fmt --all` before committing
- Ensure `cargo clippy --target aarch64-unknown-linux-gnu -- -D warnings` passes
- Follow Rust API Guidelines

## Testing

- Add tests for new features
- Run `tools/scan_repo.sh` locally before pushing
- Verify CI passes on your branch

## Pull Request Process

1. Fill out PR template completely (including AI disclosure)
2. Ensure all CI checks pass
3. Request review from maintainers
4. Address feedback promptly

## Questions?

Open an issue or email security@winncore.com
