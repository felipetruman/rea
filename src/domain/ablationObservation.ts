import { z } from "zod";

import { jsonValueSchema } from "./jsonValue.js";

/** Maximum accepted semantic-search query length in characters. */
export const ABLATION_MAX_QUERY_CHARACTERS = 2048;
/** Maximum accepted target path length in characters. */
export const ABLATION_MAX_TARGET_PATH_CHARACTERS = 4096;

const targetPathSchema = z
  .string()
  .min(1)
  .max(ABLATION_MAX_TARGET_PATH_CHARACTERS)
  .describe(
    "Absolute local path of the analysis target inside approved input roots",
  );
const querySchema = z
  .string()
  .min(1)
  .max(ABLATION_MAX_QUERY_CHARACTERS)
  .describe("Semantic function-search query");
const addressSchema = z
  .string()
  .regex(/^0x[0-9a-f]{1,16}$/u)
  .describe("Hexadecimal virtual address reported by Ablation, e.g. 0x401000");

/** Caller input for one Ablation structural analysis. */
export const ablationAnalyzeInputSchema = z
  .object({ target_path: targetPathSchema })
  .strict();
/** Caller input for one Ablation semantic function search. */
export const ablationSearchInputSchema = z
  .object({ target_path: targetPathSchema, query: querySchema })
  .strict();
/** Caller input for one Ablation source-to-sink taint investigation. */
export const ablationTaintInputSchema = z
  .object({ target_path: targetPathSchema })
  .strict();
/** Caller input for one Ablation single-function profile. */
export const ablationFunctionProfileInputSchema = z
  .object({ target_path: targetPathSchema, address: addressSchema })
  .strict();

export type AblationAnalyzeInput = z.infer<typeof ablationAnalyzeInputSchema>;
export type AblationSearchInput = z.infer<typeof ablationSearchInputSchema>;
export type AblationTaintInput = z.infer<typeof ablationTaintInputSchema>;
export type AblationFunctionProfileInput = z.infer<
  typeof ablationFunctionProfileInputSchema
>;

/** Fixed Ablation subcommand admitted by the adapter. */
export const ablationOperationNameSchema = z.enum([
  "analyze",
  "search",
  "taint",
  "profile",
]);
export type AblationOperationName = z.infer<typeof ablationOperationNameSchema>;

/** Honest coverage declaration for one Ablation observation. */
export const ablationCoverageSchema = z.enum(["unknown", "partial"]);

/** Digest-bound local target identity admitted for one operation. */
export const ablationTargetRefSchema = z
  .object({
    path: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    format: z.enum(["elf", "pe", "mach-o", "unknown"]),
    bytes: z.number().int().min(0),
  })
  .strict();
export type AblationTargetRef = z.infer<typeof ablationTargetRefSchema>;

/** Outcome of one completed controlled Ablation subprocess execution. */
export const ablationExecutionSchema = z
  .object({
    exit_code: z.number().int(),
    duration_ms: z.number().int().min(0),
    status: z.literal("completed"),
  })
  .strict();

/** Exact provenance of one Ablation observation. */
export const ablationProvenanceSchema = z
  .object({
    executable: z.string().min(1),
    version: z.string().nullable(),
    adapter_contract_version: z.literal(1),
  })
  .strict();

/** Bounded raw process output retained verbatim for diagnostics. */
export const ablationRawOutputSchema = z
  .object({ stdout: z.string(), stderr: z.string() })
  .strict();

/** Deterministically parsed finding; never synthesized from absence. */
export const ablationFindingSchema = z
  .object({
    kind: z.string().min(1),
    address: z.string().nullable(),
    detail: jsonValueSchema,
  })
  .strict();
export type AblationFinding = z.infer<typeof ablationFindingSchema>;

/** One completed auxiliary Ablation observation with full provenance. */
export const ablationOperationObservationSchema = z
  .object({
    operation: ablationOperationNameSchema,
    target: ablationTargetRefSchema,
    execution: ablationExecutionSchema,
    provenance: ablationProvenanceSchema,
    raw_output: ablationRawOutputSchema,
    coverage: ablationCoverageSchema,
    parsed: jsonValueSchema.nullable(),
    findings: z.array(ablationFindingSchema),
    limitations: z.array(z.string().min(1)),
  })
  .strict();
export type AblationOperationObservation = z.infer<
  typeof ablationOperationObservationSchema
>;

/** Run policy derived from REA configuration for the Ablation adapter. */
export interface AblationRunPolicy {
  /** Approved Ablation executable path or name resolved without a shell. */
  readonly executable: string;
  /** Canonical approved input roots; targets must resolve inside one. */
  readonly approvedRoots: readonly string[];
  /** Absolute execution deadline for one Ablation subprocess. */
  readonly timeoutMs: number;
  /** Combined stdout and stderr capture bound. */
  readonly maxOutputBytes?: number;
  /** Whether model downloads are permitted; offline flags are forced otherwise. */
  readonly allowModelDownload?: boolean;
}

/** Default per-operation timeout (REA_EXTRAS_TIMEOUT_MS default). */
/** Minimum admitted per-operation timeout. */
/** Maximum admitted per-operation timeout. */
/** Default combined output bound (2 MiB). */
export const ABLATION_DEFAULT_MAX_OUTPUT_BYTES = 2 * 1024 * 1024;

/** Subject formats the adapter can classify from magic bytes. */
