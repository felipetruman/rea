import { describe, it, expect } from "vitest";
import { parseAblationResult } from "../ablation/index.js";
import type { ProviderIdentity } from "../application/AnalysisProvider.js";
import type { AblationTargetRef } from "../domain/ablationObservation.js";

describe("AblationResultParser", () => {
  const mockIdentity: ProviderIdentity = {
    id: "ablation",
    name: "Ablation",
    version: "1.0.0",
  };

  const mockTarget: AblationTargetRef = {
    path: "/usr/bin/ls",
    sha256: "a".repeat(64),
    format: "elf",
    bytes: 1024,
  };

  it("should parse successful JSON output", () => {
    const observation = parseAblationResult({
      operation: "analyze",
      target: mockTarget,
      exitCode: 0,
      stdout: JSON.stringify({
        findings: [{ kind: "function", address: "0x401000", detail: {} }],
        coverage: "partial",
      }),
      stderr: "",
      duration_ms: 100,
      executable: "ablation",
      executableVersion: "1.0.0",
      provider: mockIdentity,
    });

    expect(observation.operation).toBe("analyze");
    expect(observation.findings.length).toBe(1);
    expect(observation.coverage).toBe("partial");
    expect(observation.limitations.length).toBe(0);
  });

  it("should add limitation on non-zero exit", () => {
    const observation = parseAblationResult({
      operation: "analyze",
      target: mockTarget,
      exitCode: 1,
      stdout: "",
      stderr: "Error occurred",
      duration_ms: 100,
      executable: "ablation",
      executableVersion: "1.0.0",
      provider: mockIdentity,
    });

    expect(observation.findings.length).toBe(0);
    expect(observation.limitations).toContain("Process exited with code 1");
  });

  it("should add limitation on invalid JSON", () => {
    const observation = parseAblationResult({
      operation: "analyze",
      target: mockTarget,
      exitCode: 0,
      stdout: "not valid json",
      stderr: "",
      duration_ms: 100,
      executable: "ablation",
      executableVersion: "1.0.0",
      provider: mockIdentity,
    });

    expect(observation.findings.length).toBe(0);
    expect(observation.limitations).toContain("Failed to parse stdout as JSON");
  });

  it("should preserve exact parsed output", () => {
    const parsedData = { custom: "field", nested: { value: 42 } };
    const observation = parseAblationResult({
      operation: "analyze",
      target: mockTarget,
      exitCode: 0,
      stdout: JSON.stringify(parsedData),
      stderr: "",
      duration_ms: 100,
      executable: "ablation",
      executableVersion: "1.0.0",
      provider: mockIdentity,
    });

    expect(observation.parsed).toEqual(parsedData);
  });

  it("should truncate large output", () => {
    const largeOutput = "x".repeat(3 * 1024 * 1024);
    const observation = parseAblationResult({
      operation: "analyze",
      target: mockTarget,
      exitCode: 0,
      stdout: largeOutput,
      stderr: "",
      duration_ms: 100,
      executable: "ablation",
      executableVersion: "1.0.0",
      provider: mockIdentity,
    });

    expect(observation.raw_output.stdout.length).toBeLessThan(
      largeOutput.length,
    );
    expect(observation.raw_output.stdout).toContain("truncated");
  });

  it("should default coverage to unknown when missing", () => {
    const observation = parseAblationResult({
      operation: "analyze",
      target: mockTarget,
      exitCode: 0,
      stdout: JSON.stringify({ findings: [] }),
      stderr: "",
      duration_ms: 100,
      executable: "ablation",
      executableVersion: "1.0.0",
      provider: mockIdentity,
    });

    expect(observation.coverage).toBe("unknown");
  });

  it("should always produce valid observation", () => {
    const observation = parseAblationResult({
      operation: "profile",
      target: mockTarget,
      exitCode: 0,
      stdout: "{}",
      stderr: "",
      duration_ms: 100,
      executable: "ablation",
      executableVersion: "1.0.0",
      provider: mockIdentity,
    });

    expect(observation.operation).toBeDefined();
    expect(observation.target).toBeDefined();
    expect(observation.execution).toBeDefined();
    expect(observation.provenance).toBeDefined();
    expect(observation.raw_output).toBeDefined();
    expect(observation.coverage).toBeDefined();
    expect(observation.findings).toBeDefined();
    expect(observation.limitations).toBeDefined();
  });
});
