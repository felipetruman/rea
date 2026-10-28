import type {
  AblationAnalyzeInput,
  AblationFunctionProfileInput,
  AblationOperationObservation,
  AblationSearchInput,
  AblationTaintInput,
} from "../domain/ablationObservation.js";
import type { AnalysisError } from "../domain/errors.js";
import type { Result } from "../domain/result.js";
import type { ExecutionOptions, ProviderIdentity } from "./AnalysisProvider.js";

/**
 * Provider-neutral application boundary for the optional Ablation auxiliary
 * provider. Implementations must authorize targets against approved input
 * roots before spawning, run the approved executable without a shell, and
 * retain provenance, raw output, coverage, and limitations for every
 * completed observation.
 */
export interface AblationObservationPort {
  identity(): ProviderIdentity;
  analyze(
    input: AblationAnalyzeInput,
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>>;
  search(
    input: AblationSearchInput,
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>>;
  taint(
    input: AblationTaintInput,
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>>;
  profile(
    input: AblationFunctionProfileInput,
    options?: ExecutionOptions,
  ): Promise<Result<AblationOperationObservation, AnalysisError>>;
}
