import {
  createEvidence,
  type Evidence,
  type EvidenceSubjectTarget,
} from "../domain/evidence.js";
import type {
  AblationFinding,
  AblationOperationObservation,
} from "../domain/ablationObservation.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { ProviderIdentity } from "./AnalysisProvider.js";

const toSubject = (
  observation: AblationOperationObservation,
): EvidenceSubjectTarget => ({
  path: observation.target.path,
  sha256: observation.target.sha256,
  format: observation.target.format,
});

const toFinding = (finding: AblationFinding): JsonValue => ({
  kind: finding.kind,
  address: finding.address,
  detail: finding.detail,
});

/** Project one completed Ablation observation into Evidence v2. */
export const createAblationEvidence = (
  operation: string,
  parameters: Readonly<Record<string, JsonValue>>,
  observation: AblationOperationObservation,
  identity: ProviderIdentity,
): Evidence =>
  createEvidence(
    toSubject(observation),
    { id: identity.id, name: identity.name, version: identity.version },
    {
      predicateType: "rea.ablation/v1",
      operation,
      parameters,
      rawResult: {
        stdout: observation.raw_output.stdout,
        stderr: observation.raw_output.stderr,
      },
      result: {
        operation: observation.operation,
        execution: observation.execution,
        provenance: observation.provenance,
        coverage: observation.coverage,
        parsed: observation.parsed,
        findings: observation.findings.map(toFinding),
        limitations: [...observation.limitations],
      },
      confidence: "observed",
      authority: "external-service",
      limitations: [...observation.limitations],
    },
  );
