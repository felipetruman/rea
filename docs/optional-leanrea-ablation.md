# Optional LeanREA and Ablation integrations

REA stays the source of truth for CLI/MCP workflows, provider selection,
authorization and Evidence v2. Ablation is an **optional auxiliary provider**,
available through both CLI commands and native MCP tools when enabled.

## Architecture

```text
OpenCode / AI Agent
        |
        v
REA MCP Server
        |
        v
Contracts + Authorization + Orchestration
        |
        +---- LeanREA (Strategy & fast triage)
        |
        +---- Deep Providers (Ghidra, Hopper, Browser, JS)
        |
        +---- Ablation Adapter (Auxiliary Provider)
              |
              v (spawn without shell, strict argv)
        Ablation CLI (Python in virtualenv)
              |
              v (stdout JSON / structured output)
        REA Structured Observation & Evidence v2
```

## Components

- **LeanREA-inspired fast paths**: low-cost magic-byte triage and bundled skill
  guidance, attributed to aicodeking/leanrea (MIT).
- **Ablation auxiliary adapter**: separate installed Python CLI process
  (GPL-3.0-or-later); we do not vendor its Python code into REA's MIT codebase.
  Subprocess separation is isolated via `spawn`, strict argument arrays, and
  path confinement.

## MCP Tools Available

When `REA_ABLATION_MCP_ENABLED="true"` is configured and the Ablation binary is diagnosed,
the following four MCP tools are announced:

1. **`ablation_analyze`**:
   - Purpose: Structural binary summary.
   - Arguments: `{ target_path: string }` (within approved roots).
   - Returns: Detected architecture, base address, function count, symbols, exports, strings count, call edges, limitations.
2. **`ablation_search`**:
   - Purpose: Semantic function search via natural language query.
   - Arguments: `{ target_path: string, query: string }` (query max 2048 chars).
   - Returns: Candidate functions with similarity scores and provenance.
3. **`ablation_taint`**:
   - Purpose: Source-to-sink data-flow investigation.
   - Arguments: `{ target_path: string }`.
   - Returns: Identified taint paths, coverage status, and limitations (empty paths do not imply safety).
4. **`ablation_function_profile`**:
   - Purpose: Profile a specific function by its virtual address.
   - Arguments: `{ target_path: string, address: string }` (hex address e.g. `0x401000`).
   - Returns: Function properties, local calls, strings, sinks, and budget metadata.

## Environment Variables

- `REA_ABLATION_MCP_ENABLED` (default `"false"`): enable MCP tool registration for Ablation.
- `REA_ABLATION_BIN` (optional): path to the Ablation CLI executable (defaults to `ablation` in `PATH`).
- `REA_INVESTIGATION_INPUT_ROOTS_JSON` (required): JSON array of absolute approved directories containing targets (e.g. `["/home/user/project","/tmp"]`).
- `REA_EXTRAS_TIMEOUT_MS` (optional, default `120000`): per-operation execution timeout in milliseconds.
- `REA_EXTRAS_ALLOW_MODEL_DOWNLOAD` (optional, default `"0"`): set to `"1"` to permit offline model caches to download if configured.

## OpenCode Configuration Example

In your OpenCode MCP settings (`~/.config/opencode/opencode.json` or workspace `mcp.json`):

```json
{
  "mcpServers": {
    "rea": {
      "command": "node",
      "args": ["/path/to/rea/dist/main.js", "mcp"],
      "env": {
        "REA_ABLATION_MCP_ENABLED": "true",
        "REA_ABLATION_BIN": "/home/user/.local/share/rea/ablation-venv/bin/ablation",
        "REA_INVESTIGATION_INPUT_ROOTS_JSON": "["/path/to/approved/binaries", "/tmp"]",
        "REA_LOG_LEVEL": "info"
      }
    }
  }
}
```

## CLI Parity Commands

The exact same underlying `AblationProvider` adapter is reused by the REA CLI:

```bash
# Doctor check
node scripts/rea.mjs extras doctor --json

# Fast file triage
node scripts/rea.mjs extras triage /path/to/binary.elf --json

# Ablation operations
node scripts/rea.mjs extras ablation analyze /path/to/binary.elf --json
node scripts/rea.mjs extras ablation search /path/to/binary.elf "crypto" --json
node scripts/rea.mjs extras ablation taint /path/to/binary.elf --json
node scripts/rea.mjs extras ablation profile /path/to/binary.elf 0x401000 --json
```

## Security & Isolation Guarantees

1. **No shell execution**: Invokes `spawn` with explicit argv arrays; zero shell interpolation.
2. **Canonical root containment**: Resolves symlinks via `realpath` and strictly validates that targets reside within `REA_INVESTIGATION_INPUT_ROOTS_JSON`.
3. **Execution limits**: Enforces absolute timeouts (`SIGTERM` -> `SIGKILL` after grace period) and caps standard output/error capture at 2 MiB.
4. **Environment isolation**: Does not pass arbitrary host credentials or dangerous flags to the subprocess.
5. **No auto-downloading**: Models are not automatically fetched without explicit opt-in.
