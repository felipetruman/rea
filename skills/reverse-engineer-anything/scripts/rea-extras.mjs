#!/usr/bin/env node
// Optional CLI bridge: LeanREA-inspired triage + external Ablation. No MCP change.
import { spawn } from "node:child_process";
import { open, realpath, stat } from "node:fs/promises";
import { extname, relative, resolve, sep } from "node:path";

const raw = process.argv.slice(2);
const args = raw[0] === "extras" ? raw.slice(1) : raw;
const LIMIT = 2 * 1024 * 1024;
function fatal(message) {
  process.stderr.write("REA extras: " + message + "\n");
  process.exitCode = 1;
}
function help() {
  process.stdout.write(
    "rea extras doctor [--json]\n" +
      "rea extras triage <file> [--json]\n" +
      "rea extras ablation analyze|taint|fmtstr <binary> [--json]\n" +
      "rea extras ablation search <binary> <query> [--json]\n" +
      "rea extras ablation window|profile|cfg <binary> <hex-address> [--json]\n" +
      "Set REA_INVESTIGATION_INPUT_ROOTS_JSON and optionally REA_ABLATION_BIN.\n",
  );
}
async function checkedTarget(input) {
  let roots;
  try {
    roots = JSON.parse(process.env.REA_INVESTIGATION_INPUT_ROOTS_JSON || "[]");
  } catch {
    throw Error("REA_INVESTIGATION_INPUT_ROOTS_JSON must be valid JSON");
  }
  if (
    !Array.isArray(roots) ||
    roots.length < 1 ||
    roots.some((x) => typeof x !== "string" || !x.startsWith("/"))
  )
    throw Error(
      "REA_INVESTIGATION_INPUT_ROOTS_JSON must contain absolute approved roots",
    );
  const file = await realpath(resolve(input));
  const metadata = await stat(file);
  if (!metadata.isFile()) throw Error("Target must be a regular file");
  const realRoots = await Promise.all(roots.map((x) => realpath(x)));
  const inside = realRoots.some((root) => {
    const rel = relative(root, file);
    return (
      rel === "" ||
      (rel !== ".." && !rel.startsWith(".." + sep) && !rel.startsWith(sep))
    );
  });
  if (!inside) throw Error("Target outside approved input roots");
  return { file, bytes: metadata.size };
}
async function fileType(file) {
  const h = await open(file, "r");
  let b = Buffer.alloc(16);
  try {
    const n = await h.read(b, 0, b.length, 0);
    b = b.subarray(0, n.bytesRead);
  } finally {
    await h.close();
  }
  const x = b.subarray(0, 4).toString("hex"),
    e = extname(file).toLowerCase();
  if (x === "7f454c46") return "ELF";
  if (x.startsWith("4d5a")) return "PE candidate";
  if (
    [
      "feedface",
      "feedfacf",
      "cefaedfe",
      "cffaedfe",
      "cafebabe",
      "bebafeca",
    ].includes(x)
  )
    return "Mach-O";
  if (x === "0061736d") return "WASM";
  if (e === ".asar") return "Electron ASAR";
  if (x.startsWith("504b"))
    return { ".apk": "APK", ".jar": "JAR", ".ipa": "IPA" }[e] || "ZIP";
  if (e === ".har") return "HAR";
  if ([".js", ".mjs", ".cjs", ".map"].includes(e)) return "JavaScript";
  if ([".pcap", ".pcapng"].includes(e)) return "PCAP";
  return "Unknown";
}
function suggestions(t) {
  if (t === "ELF")
    return [
      "file <target>",
      "readelf -hlSW <target>",
      "nm -D <target>",
      "strings -a -n 6 <target>",
      "rea extras ablation analyze <target>",
    ];
  if (t === "PE candidate")
    return [
      "objdump -x <target>",
      "strings -a <target>",
      "rea extras ablation analyze <target>",
    ];
  if (t === "Mach-O") return ["otool -L <target>", "nm -gU <target>"];
  if (t === "Electron ASAR")
    return ["Extract ASAR privately", "rg -uu to find preload and IPC routes"];
  if (t === "APK") return ["unzip -l <target>", "jadx -d <output> <target>"];
  if (t === "WASM") return ["wasm-objdump -x <target>", "wasm2wat <target>"];
  if (t === "PCAP") return ["tshark -r <target> -q -z conv,tcp"];
  return [
    "file <target>",
    "strings -a -n 6 <target>",
    "select specialized analyzer",
  ];
}
function invoke(command, argv, timeout) {
  return new Promise((finish) => {
    const env = {};
    for (const k of [
      "PATH",
      "HOME",
      "TMPDIR",
      "TEMP",
      "TMP",
      "LANG",
      "LC_ALL",
      "VIRTUAL_ENV",
      "XDG_CACHE_HOME",
      "SSL_CERT_FILE",
      "REQUESTS_CA_BUNDLE",
    ])
      if (process.env[k] !== undefined) env[k] = process.env[k];
    if (process.env.REA_EXTRAS_ALLOW_MODEL_DOWNLOAD !== "1") {
      env.HF_HUB_OFFLINE = "1";
      env.TRANSFORMERS_OFFLINE = "1";
    }
    const proc = spawn(command, argv, {
      shell: false,
      env,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "",
      stderr = "",
      bytes = 0,
      failure = "",
      finished = false;
    const collect = (chunk, isOut) => {
      bytes += chunk.length;
      if (bytes > LIMIT) {
        failure = "Output exceeded 2 MiB";
        proc.kill("SIGKILL");
        return;
      }
      if (isOut) stdout += chunk.toString("utf8");
      else stderr += chunk.toString("utf8");
    };
    proc.stdout.on("data", (v) => collect(v, true));
    proc.stderr.on("data", (v) => collect(v, false));
    const timer = setTimeout(() => {
      failure = "Timeout";
      proc.kill("SIGKILL");
    }, timeout);
    proc.once("error", (err) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        finish({
          ok: false,
          code: 1,
          stdout,
          stderr: err.message,
          reason: "spawn-failed",
        });
      }
    });
    proc.once("close", (code) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        finish({
          ok: code === 0 && !failure,
          code: code ?? 1,
          stdout,
          stderr,
          reason: failure,
        });
      }
    });
  });
}
function print(x, json) {
  process.stdout.write(
    json
      ? JSON.stringify(x, null, 2) + "\n"
      : typeof x === "string"
        ? x
        : JSON.stringify(x, null, 2) + "\n",
  );
}
async function main() {
  const json = args.includes("--json"),
    a = args.filter((x) => x !== "--json");
  if (a.length === 0 || ["help", "-h", "--help"].includes(a[0])) return help();
  if (a[0] === "doctor") {
    if (a.length !== 1) throw Error("Expected rea extras doctor [--json]");
    const bin = process.env.REA_ABLATION_BIN || "ablation";
    const r = await invoke(bin, ["--help"], 8000);
    return print(
      {
        leanrea: { available: true, mode: "bundled skill" },
        ablation: {
          available: r.ok,
          executable: bin,
          diagnostic: r.ok
            ? "CLI detected"
            : r.reason || r.stderr.slice(0, 200),
        },
        automaticInstall: false,
      },
      json,
    );
  }
  if (a[0] === "triage") {
    if (a.length !== 2) throw Error("Expected rea extras triage <file>");
    const t = await checkedTarget(a[1]),
      format = await fileType(t.file);
    return print(
      {
        target: t.file,
        bytes: t.bytes,
        format,
        recommendedCommands: suggestions(format),
        note: "Recommendations are not executed; validate every inference.",
      },
      json,
    );
  }
  if (a[0] !== "ablation") throw Error("Unknown extras command");
  const allowed = {
    analyze: 1,
    taint: 1,
    fmtstr: 1,
    search: 2,
    window: 2,
    profile: 2,
    cfg: 2,
  };
  const action = a[1],
    count = allowed[action];
  if (!count || a.length !== count + 2)
    throw Error("Unsupported Ablation command or argument count");
  const t = await checkedTarget(a[2]),
    pass = [action, t.file];
  if (count === 2) {
    const v = a[3];
    if (action !== "search" && !/^0x[0-9a-f]{1,16}$/i.test(v))
      throw Error("Address must be a hex VA, e.g. 0x401000");
    if (action === "search" && (v.length < 1 || v.length > 2048))
      throw Error("Query must be between 1 and 2048 characters");
    pass.push(v);
  }
  const n = Number(process.env.REA_EXTRAS_TIMEOUT_MS || 120000);
  const timeout = Number.isFinite(n)
    ? Math.min(600000, Math.max(1000, n))
    : 120000;
  const result = await invoke(
    process.env.REA_ABLATION_BIN || "ablation",
    pass,
    timeout,
  );
  if (json)
    print({ tool: "ablation", action, target: t.file, ...result }, true);
  else {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.reason) process.stderr.write(result.reason + "\n");
  }
  if (!result.ok) process.exitCode = 1;
}
main().catch((e) => fatal(e?.message || String(e)));
