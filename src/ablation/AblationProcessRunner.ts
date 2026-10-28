import { spawn } from "node:child_process";
import type { AblationOperationName } from "../domain/ablationObservation.js";
import { ABLATION_DEFAULT_MAX_OUTPUT_BYTES } from "../domain/ablationObservation.js";
import type { AnalysisError } from "../domain/errors.js";
import {
  AnalysisOutputError,
  AnalysisTimeoutError,
  AnalysisCancelledError,
} from "../domain/errors.js";
import type { Result } from "../domain/result.js";
import { err, ok } from "../domain/result.js";

export interface AblationProcessResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly duration_ms: number;
}

/**
 * Execute Ablation without shell, with timeout TERM→KILL and bounded output.
 */
// oxlint-disable-next-line max-lines-per-function
export async function runAblationProcess(options: {
  readonly executable: string;
  readonly operation: AblationOperationName;
  readonly targetPath: string;
  readonly query?: string | undefined;
  readonly address?: string | undefined;
  readonly timeoutMs: number;
  readonly maxOutputBytes?: number | undefined;
  readonly signal?: AbortSignal | undefined;
}): Promise<Result<AblationProcessResult, AnalysisError>> {
  const {
    executable,
    operation,
    targetPath,
    query,
    address,
    timeoutMs,
    maxOutputBytes = ABLATION_DEFAULT_MAX_OUTPUT_BYTES,
    signal,
  } = options;

  // Build argv without shell
  const argv: string[] = [operation, targetPath];
  if (query !== undefined && query.length > 0) argv.push("--query", query);
  if (address !== undefined && address.length > 0)
    argv.push("--address", address);

  const startTime = Date.now();
  let resolvePromise!: (
    result: Result<AblationProcessResult, AnalysisError>,
  ) => void;
  const promise = new Promise<Result<AblationProcessResult, AnalysisError>>(
    (res) => {
      resolvePromise = res;
    },
  );
  let completed = false;

  const settle = (result: Result<AblationProcessResult, AnalysisError>) => {
    if (completed) return;
    completed = true;
    clearTimeout(timeout);
    signal?.removeEventListener("abort", onAbort);
    resolvePromise(result);
  };

  let stdout = "";
  let stderr = "";
  let outputBytes = 0;
  let timedOut = false;
  let cancelled = false;

  const onAbort = () => {
    cancelled = true;
    child.kill("SIGTERM");
  };

  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
  }, timeoutMs);

  const child = spawn(executable, argv, {
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout?.on("data", (chunk: Buffer) => {
    outputBytes += chunk.length;
    if (outputBytes <= maxOutputBytes) {
      stdout += chunk.toString("utf-8", 0, maxOutputBytes - outputBytes);
    }
  });

  child.stderr?.on("data", (chunk: Buffer) => {
    outputBytes += chunk.length;
    if (outputBytes <= maxOutputBytes) {
      stderr += chunk.toString("utf-8", 0, maxOutputBytes - outputBytes);
    }
  });

  child.on("error", (childError) => {
    settle(
      err(
        new AnalysisOutputError(
          `ablation:${operation}`,
          `Process error: ${childError.message}`,
          { cause: childError },
        ),
      ),
    );
  });

  child.on("exit", (exitCode) => {
    const duration_ms = Date.now() - startTime;

    if (cancelled) {
      return settle(err(new AnalysisCancelledError(`ablation:${operation}`)));
    }

    if (timedOut) {
      return settle(
        err(new AnalysisTimeoutError(`ablation:${operation}`, timeoutMs)),
      );
    }

    return settle(
      ok({
        exitCode: exitCode ?? 0,
        stdout,
        stderr,
        duration_ms,
      }),
    );
  });

  signal?.addEventListener("abort", onAbort, { once: true });

  return promise;
}
