# Optional LeanREA and Ablation integrations

REA stays the source of truth for CLI/MCP workflows, provider selection,
authorization and Evidence v2. These are **CLI-only opt-in integrations**, not
native MCP tools or an Ablation deep provider.

## Components

- LeanREA-inspired low-cost magic-byte triage and bundled skill guidance,
  attributed to aicodeking/leanrea (MIT).
- Ablation as a **separate installed Python CLI process** (GPL-3.0-or-later);
  we do not vendor its Python code. Subprocess separation is not a legal opinion
  on license compatibility.

## Local setup (Linux/macOS, manual opt-in)

From a trusted REA checkout, use Node 22.19+ and Python 3.10+. The pinned
PyPI example below refers to the previously reviewed published release; newer
GitHub releases may have other capabilities.

    python3 -m venv .rea-ablation-venv
    .rea-ablation-venv/bin/python -m pip install 'ablation-tool==2.81.0'
    export REA_ABLATION_BIN="$PWD/.rea-ablation-venv/bin/ablation"
    export REA_INVESTIGATION_INPUT_ROOTS_JSON='["/absolute/path/to/approved/targets"]'
    node scripts/rea.mjs extras doctor --json
    node scripts/rea.mjs extras triage /absolute/path/to/approved/targets/app.elf --json
    node scripts/rea.mjs extras ablation analyze /absolute/path/to/approved/targets/app.elf
    node scripts/rea.mjs extras ablation search /absolute/path/to/approved/targets/app.elf "parse input"

Once REA is installed from this fork, replace node scripts/rea.mjs with rea.
LeanREA guidance is installed with the existing reverse-engineer-anything skill.
The extras dispatcher works even without dist/cli.js or an MCP server.

## Boundaries and caveats

- Explicit path roots are mandatory. Canonical paths and resolved symlinks
  must stay inside the provided root; only regular files are admitted.
- Only fixed diagnostic Ablation subcommands are exposed: analyze, search,
  window, profile, cfg, taint, fmtstr. No arbitrary flags and no shell.
- Timeout defaults to 120s (REA_EXTRAS_TIMEOUT_MS, max 600s); total output
  is bounded to 2 MiB. Only a restricted process environment is forwarded.
- External embedding downloads are disabled by default. To allow download
  of the semantic model, set REA_EXTRAS_ALLOW_MODEL_DOWNLOAD=1.
- This is **not** a hardened OS sandbox. Use a disposable VM/container
  with filesystem and network isolation for untrusted artifacts.
- An empty scan, a heuristic hit or an unsupported format is never proof
  of safety. Validate observations and retain scope/coverage limitations.
- Remote web and API security probes from Ablation modules/api_re.py
  are intentionally excluded because they require separate authorization,
  rate-limit controls, and non-destructive test profiles.
- This does not provide MCP parity, managed installation, or real Ablation
  end-to-end validation. It provides CLI integration and mock-tested
  process composition only.

## Verification

    node --test tests/extras-integration.test.mjs
