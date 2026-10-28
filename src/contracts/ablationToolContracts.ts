import { z } from "zod";
import {
  ablationAnalyzeInputSchema,
  ablationSearchInputSchema,
  ablationTaintInputSchema,
  ablationFunctionProfileInputSchema,
  ablationOperationObservationSchema,
} from "../domain/ablationObservation.js";
import { toolContractMetadata } from "./toolEffects.js";
import { examplesFor } from "./toolContractHelpers.js";
import type { ToolContract } from "./toolContractTypes.js";
import { evidenceResultOf } from "./toolOutputSchemas.js";

const ablationOutputSchema = evidenceResultOf(
  ablationOperationObservationSchema,
);

const enhanced = <Name extends string, Schema extends z.ZodObject>(
  name: Name,
  description: string,
  inputSchema: Schema,
) =>
  ({
    name,
    ...toolContractMetadata(name),
    description,
    kind: "enhanced",
    inputSchema,
    outputSchema: ablationOutputSchema,
    examples: examplesFor(name, inputSchema),
  }) satisfies ToolContract<Name, Schema>;

/** Ablation auxiliary reverse-engineering contracts. */
export const ABLATION_TOOL_CONTRACTS = [
  enhanced(
    "ablation_analyze",
    "Run one authorized Ablation structural analysis on an approved target binary. Returns parsed findings and provenance with full execution metadata, raw output, coverage assessment, and limitations.",
    ablationAnalyzeInputSchema,
  ),
  enhanced(
    "ablation_search",
    "Run one authorized Ablation semantic function search on an approved target binary using a natural-language query. Returns function candidates with relevance scores, provenance, and operation budget.",
    ablationSearchInputSchema,
  ),
  enhanced(
    "ablation_taint",
    "Run one authorized Ablation source-to-sink taint investigation on an approved target binary. Returns taint paths, provenance, coverage, and limitations on data-flow inference.",
    ablationTaintInputSchema,
  ),
  enhanced(
    "ablation_function_profile",
    "Run one authorized Ablation single-function profile on an approved target binary at an explicit virtual address. Returns detailed function properties, operation budget, and execution metadata.",
    ablationFunctionProfileInputSchema,
  ),
] as const satisfies readonly ToolContract[];
