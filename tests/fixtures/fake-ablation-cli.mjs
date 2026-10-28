#!/usr/bin/env node
/**
 * Deterministic fake Ablation CLI for adapter testing.
 * Modes: --help, analyze, search, taint, profile.
 * All JSON returns include valid operation observation structure.
 */

const args = process.argv.slice(2);
const mode = args[0];

const exit = (code, output) => {
  if (output) {
    process.stdout.write(output);
  }
  process.exit(code);
};

// Simulate startup time for timeout tests
if (process.env.FAKE_ABLATION_STARTUP_DELAY_MS) {
  const delay = parseInt(process.env.FAKE_ABLATION_STARTUP_DELAY_MS, 10);
  if (Number.isFinite(delay) && delay > 0) {
    const start = Date.now();
    while (Date.now() - start < delay) {
      // Busy loop
    }
  }
}

// Simulate ignore SIGTERM (for signal handling tests)
if (process.env.FAKE_ABLATION_IGNORE_SIGTERM) {
  process.on("SIGTERM", () => {
    // Ignore
  });
}

if (mode === "--help" || mode === "-h") {
  exit(
    0,
    "Fake Ablation 1.0.0\nUsage: ablation [analyze|search|taint|profile] <target>\n",
  );
}

if (mode === "--version") {
  exit(0, "1.0.0\n");
}

if (!args[1]) {
  exit(2, "Error: target path required\n");
}

// const target = args[1];
// const query = args[2];

// Mode: invalid output
if (process.env.FAKE_ABLATION_INVALID_JSON === "true") {
  exit(0, "not valid json at all");
}

// Mode: output exceeding limit (simulated in runner via bytes cap)
if (process.env.FAKE_ABLATION_HUGE_OUTPUT === "true") {
  const chunk = "x".repeat(10000);
  for (let i = 0; i < 300; i++) {
    process.stdout.write(chunk);
  }
  exit(0, "");
}

// Mode: non-zero exit
if (process.env.FAKE_ABLATION_EXIT_CODE) {
  const code = parseInt(process.env.FAKE_ABLATION_EXIT_CODE, 10);
  exit(code, JSON.stringify({ error: "simulated failure" }));
}

// Mode: missing fields (valid JSON but incomplete observation)
if (process.env.FAKE_ABLATION_MISSING_FIELDS === "true") {
  exit(0, JSON.stringify({ findings: [] }));
}

// Normal successful response
const observation = {
  findings: [
    {
      kind: "function",
      address: "0x401000",
      detail: { name: "main", size: 256 },
    },
  ],
  coverage: "partial",
  limitations: ["simulation mode"],
};

exit(0, JSON.stringify(observation));
