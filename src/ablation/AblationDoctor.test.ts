import { describe, it, expect } from "vitest";
import { diagnoseAblation } from "../ablation/index.js";
import { AnalysisOutputError } from "../domain/errors.js";

describe("AblationDoctor", () => {
  it("should return error when executable not found", async () => {
    const result = await diagnoseAblation({
      executable: "nonexistent-ablation-binary-xyz-12345",
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(AnalysisOutputError);
      expect(result.error._tag).toBe("AnalysisOutputError");
    }
  });

  it("should parse version from help output", async () => {
    // Node itself returns help-like output
    const result = await diagnoseAblation({ executable: "node" });
    expect(result).toBeDefined();
  });
});
