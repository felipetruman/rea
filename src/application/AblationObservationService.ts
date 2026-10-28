import {
  ablationAnalyzeInputSchema,
  ablationFunctionProfileInputSchema,
  ablationSearchInputSchema,
  ablationTaintInputSchema,
} from "../domain/ablationObservation.js";
import type { Evidence } from "../domain/evidence.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  type AnalysisError,
} from "../domain/errors.js";
import { projectInputIssues } from "../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../domain/result.js";
import type { ExecutionOptions } from "./AnalysisProvider.js";
import { createAblationEvidence } from "./AblationEvidence.js";
import type { AblationObservationPort } from "./AblationObservationPort.js";

export type AblationToolName =
  | "ablation_analyze"
  | "ablation_search"
  | "ablation_taint"
  | "ablation_function_profile";

const ABLATION_PROVIDER_ID = "ablation";
const ABLATION_UNAVAILABLE_REASON =
  "Ablation MCP tools are enabled, but the Ablation CLI is not available. Point REA_ABLATION_BIN at an approved installed ablation executable (see docs/optional-leanrea-ablation.md) and retry.";

const requireAblation = (
  ablation: AblationObservationPort | undefined,
  operation: AblationToolName,
): Result<AblationObservationPort, AnalysisError> =>
  ablation === undefined
    ? err(
        new AnalysisCapabilityUnavailableError(
          ABLATION_PROVIDER_ID,
          operation,
          ABLATION_UNAVAILABLE_REASON,
        ),
      )
    : ok(ablation);

/** Run one authorized Ablation structural analysis and record its evidence. */
export const runAblationAnalyze = async (
  ablation: AblationObservationPort | undefined,
  rawInput: unknown,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const parsed = ablationAnalyzeInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      new AnalysisInputError(
        "ablation_analyze",
        undefined,
        projectInputIssues(parsed.error.issues, rawInput),
      ),
    );
  const ready = requireAblation(ablation, "ablation_analyze");
  if (!ready.ok) return ready;
  const result = await ready.value.analyze(parsed.data, options);
  return result.ok
    ? ok(
        createAblationEvidence(
          "ablation_analyze",
          { target_path: parsed.data.target_path },
          result.value,
          ready.value.identity(),
        ),
      )
    : result;
};

/** Run one authorized Ablation semantic function search. */
export const runAblationSearch = async (
  ablation: AblationObservationPort | undefined,
  rawInput: unknown,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const parsed = ablationSearchInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      new AnalysisInputError(
        "ablation_search",
        undefined,
        projectInputIssues(parsed.error.issues, rawInput),
      ),
    );
  const ready = requireAblation(ablation, "ablation_search");
  if (!ready.ok) return ready;
  const result = await ready.value.search(parsed.data, options);
  return result.ok
    ? ok(
        createAblationEvidence(
          "ablation_search",
          { target_path: parsed.data.target_path, query: parsed.data.query },
          result.value,
          ready.value.identity(),
        ),
      )
    : result;
};

/** Run one authorized Ablation taint investigation. */
export const runAblationTaint = async (
  ablation: AblationObservationPort | undefined,
  rawInput: unknown,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const parsed = ablationTaintInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      new AnalysisInputError(
        "ablation_taint",
        undefined,
        projectInputIssues(parsed.error.issues, rawInput),
      ),
    );
  const ready = requireAblation(ablation, "ablation_taint");
  if (!ready.ok) return ready;
  const result = await ready.value.taint(parsed.data, options);
  return result.ok
    ? ok(
        createAblationEvidence(
          "ablation_taint",
          { target_path: parsed.data.target_path },
          result.value,
          ready.value.identity(),
        ),
      )
    : result;
};

/** Run one authorized Ablation single-function profile. */
export const runAblationFunctionProfile = async (
  ablation: AblationObservationPort | undefined,
  rawInput: unknown,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const parsed = ablationFunctionProfileInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      new AnalysisInputError(
        "ablation_function_profile",
        undefined,
        projectInputIssues(parsed.error.issues, rawInput),
      ),
    );
  const ready = requireAblation(ablation, "ablation_function_profile");
  if (!ready.ok) return ready;
  const result = await ready.value.profile(parsed.data, options);
  return result.ok
    ? ok(
        createAblationEvidence(
          "ablation_function_profile",
          {
            target_path: parsed.data.target_path,
            address: parsed.data.address,
          },
          result.value,
          ready.value.identity(),
        ),
      )
    : result;
};
