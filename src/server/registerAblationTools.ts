import type { McpServer, ServerContext } from "@modelcontextprotocol/server";

import type { BinarySessionPort } from "../application/BinarySession.js";
import {
  runAblationAnalyze,
  runAblationSearch,
  runAblationTaint,
  runAblationFunctionProfile,
} from "../application/AblationObservationService.js";
import type { AnalysisError } from "../domain/errors.js";
import type { Evidence } from "../domain/evidence.js";
import type { Result } from "../domain/result.js";
import { ABLATION_TOOL_CONTRACTS } from "../contracts/ablationToolContracts.js";
import type { ToolContract } from "../contracts/toolContracts.js";
import type { AblationObservationPort } from "../application/AblationObservationPort.js";
import type { Logger } from "../logger.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { toCallToolResult } from "./toolResult.js";

interface AblationToolRegistration {
  readonly logger: Logger;
  readonly ablation: AblationObservationPort | undefined;
  readonly recordEvidence: BinarySessionPort["recordEvidence"] | undefined;
}

interface AblationToolContext {
  readonly signal: AbortSignal;
}

/** Register Ablation tools when capability is available, hide when unavailable. */
export const registerAblationTools = (
  server: McpServer,
  options: AblationToolRegistration,
): void => {
  const [analyzeContract, searchContract, taintContract, profileContract] =
    ABLATION_TOOL_CONTRACTS;

  server.registerTool(
    analyzeContract.name,
    toolRegistrationOptions(analyzeContract),
    (input, context) =>
      runAblationTool(
        options,
        analyzeContract,
        { input, context },
        (parsed, { signal }) =>
          runAblationAnalyze(options.ablation, parsed, { signal }),
      ),
  );
  server.registerTool(
    searchContract.name,
    toolRegistrationOptions(searchContract),
    (input, context) =>
      runAblationTool(
        options,
        searchContract,
        { input, context },
        (parsed, { signal }) =>
          runAblationSearch(options.ablation, parsed, { signal }),
      ),
  );
  server.registerTool(
    taintContract.name,
    toolRegistrationOptions(taintContract),
    (input, context) =>
      runAblationTool(
        options,
        taintContract,
        { input, context },
        (parsed, { signal }) =>
          runAblationTaint(options.ablation, parsed, { signal }),
      ),
  );
  server.registerTool(
    profileContract.name,
    toolRegistrationOptions(profileContract),
    (input, context) =>
      runAblationTool(
        options,
        profileContract,
        { input, context },
        (parsed, { signal }) =>
          runAblationFunctionProfile(options.ablation, parsed, { signal }),
      ),
  );
};

const runAblationTool = async <Input>(
  options: AblationToolRegistration,
  contract: ToolContract,
  request: { readonly input: Input; readonly context: ServerContext },
  execute: (
    input: Input,
    context: AblationToolContext,
  ) => Promise<Result<Evidence, AnalysisError>>,
): Promise<any> => {
  const { input, context } = request;
  const result = await logToolExecution(options.logger, contract.name, () =>
    execute(input, {
      signal: context.mcpReq.signal,
    }),
  );
  if (!result.ok) return toCallToolResult(result, contract);
  return evidenceResult(options, contract, result.value);
};

const evidenceResult = (
  options: AblationToolRegistration,
  contract: ToolContract,
  evidence: Evidence,
) => {
  const recorded = options.recordEvidence?.(evidence);
  return recorded !== undefined && !recorded.ok
    ? toCallToolResult(recorded, contract)
    : toCallToolResult({ ok: true, value: evidence }, contract, {
        evidenceResourcesAvailable: recorded !== undefined,
      });
};
