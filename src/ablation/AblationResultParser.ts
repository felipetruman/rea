import type {
  AblationOperationObservation,
  AblationOperationName,
  AblationTargetRef,
  AblationFinding,
} from "../domain/ablationObservation.js";
import {
  ablationOperationObservationSchema,
  ABLATION_DEFAULT_MAX_OUTPUT_BYTES,
} from "../domain/ablationObservation.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { ProviderIdentity } from "../application/AnalysisProvider.js";

export interface ParseAblationResultOptions {
  readonly operation: AblationOperationName;
  readonly target: AblationTargetRef;
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly duration_ms: number;
  readonly executable: string;
  readonly executableVersion: string | null;
  readonly provider: ProviderIdentity;
}

/**
 * Parse Ablation subprocess output into a complete observation.
 * Never synthesizes findings; preserves exact output and limitations.
 */
export function parseAblationResult(
  options: ParseAblationResultOptions,
): AblationOperationObservation {
  const {
    operation,
    target,
    exitCode,
    stdout,
    stderr,
    duration_ms,
    executable,
    executableVersion,
  } = options;

  // Attempt JSON parse only if exit code is 0
  let parsed: JsonValue | null = null;
  const limitations: string[] = [];

  if (exitCode === 0) {
    try {
      parsed = JSON.parse(stdout) as JsonValue;
    } catch {
      limitations.push("Failed to parse stdout as JSON");
      parsed = null;
    }
  } else {
    limitations.push(`Process exited with code ${exitCode}`);
  }

  // Extract findings and coverage from parsed result if available
  const findings: AblationFinding[] = [];
  let coverage: "unknown" | "partial" = "unknown";

  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const obj = parsed as Record<string, unknown>;

    if (Array.isArray(obj.findings)) {
      for (const f of obj.findings) {
        if (typeof f === "object" && f !== null) {
          const finding = f as Record<string, unknown>;
          findings.push({
            kind: String(finding.kind ?? "unknown"),
            address:
              finding.address === null || finding.address === undefined
                ? null
                : String(finding.address),
            detail: (finding.detail as JsonValue) ?? null,
          });
        } else {
          findings.push({
            kind: "unknown",
            address: null,
            detail: null,
          });
        }
      }
    }

    if (obj.coverage === "partial" || obj.coverage === "unknown") {
      coverage = obj.coverage;
    }
  }

  // Bounded output retention
  const maxOutput = ABLATION_DEFAULT_MAX_OUTPUT_BYTES;
  const boundedStdout =
    stdout.length > maxOutput
      ? stdout.slice(0, maxOutput) + `\n... (truncated, ${stdout.length} total)`
      : stdout;
  const boundedStderr =
    stderr.length > maxOutput
      ? stderr.slice(0, maxOutput) + `\n... (truncated, ${stderr.length} total)`
      : stderr;

  const observation: AblationOperationObservation = {
    operation,
    target,
    execution: {
      exit_code: exitCode,
      duration_ms,
      status: "completed",
    },
    provenance: {
      executable,
      version: executableVersion,
      adapter_contract_version: 1,
    },
    raw_output: {
      stdout: boundedStdout,
      stderr: boundedStderr,
    },
    coverage,
    parsed,
    findings,
    limitations,
  };

  // Validate against schema
  try {
    ablationOperationObservationSchema.parse(observation);
  } catch (validationError) {
    // Schema failure should not occur if we've built it correctly,
    // but if it does, record it as a limitation
    limitations.push(`Schema validation failed: ${String(validationError)}`);
  }

  return observation;
}
