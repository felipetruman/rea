import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { ProviderIdentity } from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/errors.js";
import { AnalysisOutputError } from "../domain/errors.js";
import type { Result } from "../domain/result.js";
import { err, ok } from "../domain/result.js";

const execFileAsync = promisify(execFile);

/**
 * Detect and diagnose the Ablation executable via env or PATH.
 * Returns ProviderIdentity on success or AnalysisError if not found/broken.
 */
export async function diagnoseAblation(options?: {
  readonly executable?: string;
}): Promise<Result<ProviderIdentity, AnalysisError>> {
  const executableName = options?.executable ?? "ablation";

  try {
    // Call --help to detect version without side effects
    const { stdout } = await execFileAsync(executableName, ["--help"], {
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
      // Do not use shell
    });

    // Parse version from help output: "Ablation <version>" or similar
    const versionMatch = stdout.match(/Ablation\s+([\d.]+)/i);
    const version = versionMatch?.[1] ?? null;

    return ok({
      id: "ablation",
      name: "Ablation",
      version,
    });
  } catch (thrown) {
    // Detect specific error types
    const cause = thrown instanceof Error ? thrown : new Error(String(thrown));
    let message = "Ablation executable not found or failed";

    if (cause.message.includes("ENOENT")) {
      message = `Ablation not found in PATH: ${executableName}`;
    } else if (cause.message.includes("timeout")) {
      message = `Ablation --help timed out`;
    }

    return err(new AnalysisOutputError("ablation:health", message, { cause }));
  }
}
