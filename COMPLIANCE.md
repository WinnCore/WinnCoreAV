# Compliance and AI Provenance Policy

## License

WinnCoreAV is licensed under the **MIT License**. See [LICENSE](LICENSE).

## AI-Assisted Development Disclosure

This project uses AI-assisted development tools. All AI-generated content is:

1. **Human-reviewed and edited** before merge
2. **Disclosed in PR metadata** (see PR template)
3. **Subject to MIT license** (no additional restrictions)

### AI Provider Matrix

Contributors must disclose AI tool usage per PR. Reference template:

| Provider | Model | Version | ToS | Output IP | Training Opt-out | Indemnity |
|----------|-------|---------|-----|-----------|------------------|-----------|
| Anthropic | Claude | 3.5 Sonnet | [Link](https://www.anthropic.com/legal/commercial-terms) | User owns | Yes | Limited |
| OpenAI | GPT-4 | - | [Link](https://openai.com/policies/terms-of-use) | User owns | Opt-in | Limited |
| GitHub | Copilot | - | [Link](https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features#github-copilot) | User owns | Configurable | See ToS |

*Update this table as new providers are used.*

## Prompt and Provenance Policy

### Public Prompts

Prompts shared publicly (e.g., in docs or examples) are licensed under **CC BY 4.0** unless stated otherwise.

### Private Prompts

Prompts not published remain **confidential** to the contributor. Disclosure in PR template is sufficient.

### Required PR Disclosure Fields

Every PR must complete the checklist in `.github/pull_request_template.md`:

- [ ] AI assistance used? (yes/no)
- [ ] If yes, provider(s): ___________
- [ ] If yes, prompt location (public URL or "confidential"): ___________
- [ ] Human authorship summary: ___________
- [ ] Third-party code/IP included? (yes/no)
- [ ] If yes, license compatibility verified: ___________

## Provenance Logging

Maintainers log AI-assisted commits in `docs/AI_PROVENANCE.md` (optional) or in commit messages with tags:
```
feat(core): add heuristic scoring

AI-Assisted: Claude 3.5 Sonnet
Prompt: confidential
Human-Edit: 60% new logic, 40% AI scaffold
```

## License Compatibility Policy

### Allowed Licenses (dependencies)

- MIT
- Apache-2.0
- BSD-3-Clause
- ISC
- Unlicense

### Prohibited Licenses

- GPL-2.0, GPL-3.0 (copyleft)
- AGPL-3.0 (copyleft)
- LGPL (static linking concerns)
- Proprietary/closed-source (without explicit approval)

**Enforcement:** `cargo-deny` in CI (`policy.yml`)

## Similarity and License Scanning

### Automated Scans

1. **cargo-deny** — Rust crate licenses and advisories
2. **gitleaks** — Secrets detection
3. **ripgrep** — GPL banner detection, EICAR pattern blocking
4. **tools/scan_repo.sh** — Comprehensive local scan

### Manual Review Process

For large AI-assisted PRs (>500 lines):

1. Run `tools/scan_repo.sh` locally
2. Sample 20% of code for similarity checks against common patterns
3. Verify human authorship claim (spot-check logic, variable naming)
4. Check for leaked proprietary patterns (API keys, internal tool references)

## SBOM Generation

Generate Software Bill of Materials quarterly or before releases:
```bash
cargo install cargo-sbom
cargo sbom > SBOM.json
```

**Retention:** SBOMs stored in `docs/sbom/` with version tags.

## Human Authorship Guidance

### Sufficient Human Contribution

Code is considered "authored" by the contributor if:

- Logic flow and design decisions are human-directed
- Variable names, error messages, and comments are human-written
- AI output is scaffolding, not verbatim copy-paste
- Human can explain the code under review

### Jurisdictional Notes

- **US:** Copyright Office guidance (March 2023) requires "human authorship" for copyright. AI-assisted code with substantial human contribution likely qualifies.
- **EU:** Pending AI Act may impose disclosure requirements. Our policy exceeds current minimums.
- **Other:** Contributors warrant compliance with local IP laws.

## Contributor Warranty

By submitting a PR, contributors warrant:

1. They have rights to contribute the code
2. AI-assisted code is disclosed per template
3. No third-party confidential information included without authorization
4. Output is compatible with MIT license
5. They have reviewed AI ToS for IP ownership

See [CONTRIBUTING.md](CONTRIBUTING.md) for DCO/CLA details.

## Indemnification

WinnCoreAV is provided AS-IS under MIT with no warranties. Contributors and users indemnify maintainers against claims arising from AI-generated content, per standard MIT terms.

## Changes to This Policy

Policy updates require maintainer approval and are effective immediately upon merge to `main`.

## Questions

Contact: security@winncore.com (for legal/compliance inquiries)

---

**Last Updated:** 2025-10-30  
**Version:** 1.0
