import type {
  AblationAnalyzeInput,
  AblationFunctionProfileInput,
  AblationOperationObservation,
  AblationSearchInput,
  AblationTaintInput,
} from "../domain/ablationObservation.js";
import type { AnalysisError } from "../domain/errors.js";
import { AnalysisCancelledError } from "../domain/errors.js";
import type { Result } from "../domain/result.js";
import { err, ok } from "../domain/result.js";
import type { ProviderIdentity } from "../application/AnalysisProvider.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { AblationObservationPort } from "../application/AblationObservationPort.js";
import type { AblationRunPolicy } from "../domain/ablationObservation.js";
import { authorizeAblationTarget } from "./AblationTargetAuthorization.js";
import { runAblationProcess } from "./AblationProcessRunner.js";
import { parseAblationResult } from "./AblationResultParser.js";

/**
 * Implements AblationObservationPort: authorizes targets, runs operations, and returns observations.
 */
export class AblationProvider implements AblationObservationPort {
  readonly #identity: ProviderIdentity;
  readonly #policy: AblationRunPolicy;

  constructor(identity: ProviderIdentity, policy: AblationRunPolicy) {
    this.#identity = identity;
    this.#policy = policy;
  }

  identity(): ProviderIdentity {
    return this.#identity;
  }

  async analyze(
    input: AblationAnalyzeInput,
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>> {
    return this.#executeOperation("analyze", input, options);
  }

  async search(
    input: AblationSearchInput,
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>> {
    return this.#executeOperation("search", input, options);
  }

  async taint(
    input: AblationTaintInput,
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>> {
    return this.#executeOperation("taint", input, options);
  }

  async profile(
    input: AblationFunctionProfileInput,
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>> {
    return this.#executeOperation("profile", input, options);
  }

  async #executeOperation(
    operation: "analyze" | "search" | "taint" | "profile",
    input: {
      readonly target_path: string;
      readonly query?: string;
      readonly address?: string;
    },
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>> {
    // Check for early abort
    if (options?.signal?.aborted) {
      return err(new AnalysisCancelledError(`ablation:${operation}`));
    }

    // Authorize target
    const targetAuth = await authorizeAblationTarget(
      input.target_path,
      this.#policy.approvedRoots,
    );
    if (!targetAuth.ok) return err(targetAuth.error);
    const target = targetAuth.value;

    // Run process
    const processResult = await runAblationProcess({
      executable: this.#policy.executable,
      operation,
      targetPath: target.path,
      query: operation === "search" ? input.query : undefined,
      address: operation === "profile" ? input.address : undefined,
      timeoutMs: this.#policy.timeoutMs,
      maxOutputBytes: this.#policy.maxOutputBytes,
      signal: options?.signal,
    });

    if (!processResult.ok) return err(processResult.error);
    const { exitCode, stdout, stderr, duration_ms } = processResult.value;

    // Parse and return observation (never fails, always produces valid observation)
    const observation = parseAblationResult({
      operation,
      target,
      exitCode,
      stdout,
      stderr,
      duration_ms,
      executable: this.#policy.executable,
      executableVersion: this.#identity.version,
      provider: this.#identity,
    });

    return ok(observation);
  }
}

/**
 * Factory to create AblationProvider from policy.
 */
export function createAblationProvider(
  identity: ProviderIdentity,
  policy: AblationRunPolicy,
): AblationProvider {
  return new AblationProvider(identity, policy);
}
