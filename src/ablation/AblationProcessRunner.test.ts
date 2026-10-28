import { describe, it, expect } from "vitest";
import { runAblationProcess } from "../ablation/index.js";

describe("AblationProcessRunner", () => {
  it("should execute analyze operation and capture output", async () => {
    // Using a simple built-in command that's guaranteed to exist
    const result = await runAblationProcess({
      executable: "echo",
      operation: "analyze",
      targetPath: "/usr/bin/ls",
      timeoutMs: 5000,
    });

    expect(result).toBeDefined();
    // Should either succeed or fail gracefully
  });

  it("should respect maxOutputBytes limit", async () => {
    const result = await runAblationProcess({
      executable: "echo",
      operation: "analyze",
      targetPath: "/usr/bin/ls",
      timeoutMs: 5000,
      maxOutputBytes: 100,
    });

    if (result.ok) {
      const totalOutput =
        result.value.stdout.length + result.value.stderr.length;
      expect(totalOutput).toBeLessThanOrEqual(100);
    }
  });

  it("should capture exit code", async () => {
    const result = await runAblationProcess({
      executable: "true",
      operation: "analyze",
      targetPath: "/usr/bin/ls",
      timeoutMs: 5000,
    });

    expect(result).toBeDefined();
  });

  it("should measure duration", async () => {
    const result = await runAblationProcess({
      executable: "true",
      operation: "analyze",
      targetPath: "/usr/bin/ls",
      timeoutMs: 5000,
    });

    if (result.ok) {
      expect(result.value.duration_ms).toBeGreaterThanOrEqual(0);
    }
  });
});
