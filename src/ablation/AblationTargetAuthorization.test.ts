import { describe, it, expect, beforeAll } from "vitest";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { authorizeAblationTarget } from "../ablation/index.js";
import { AnalysisInputError } from "../domain/errors.js";

describe("AblationTargetAuthorization", () => {
  let tempDir: string;
  let testBinary: string;

  beforeAll(() => {
    tempDir = join(tmpdir(), `ablation-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });

    // Create a test binary with ELF magic
    testBinary = join(tempDir, "test.bin");
    const elfMagic = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
    writeFileSync(testBinary, elfMagic);
  });

  it("should authorize a file within approved roots", async () => {
    const result = await authorizeAblationTarget(testBinary, [tempDir]);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.format).toBe("elf");
      expect(result.value.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(result.value.bytes).toBeGreaterThan(0);
    }
  });

  it("should reject empty target path", async () => {
    const result = await authorizeAblationTarget("", [tempDir]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(AnalysisInputError);
      expect(result.error._tag).toBe("AnalysisInputError");
    }
  });

  it("should reject target outside approved roots", async () => {
    const result = await authorizeAblationTarget("/etc/passwd", [tempDir]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisInputError");
    }
  });

  it("should reject directory instead of file", async () => {
    const result = await authorizeAblationTarget(tempDir, [tempDir]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisInputError");
    }
  });

  it("should detect PE format from magic bytes", async () => {
    const peBinary = join(tempDir, "test.exe");
    const peMagic = Buffer.from([0x4d, 0x5a]);
    writeFileSync(peBinary, peMagic);

    const result = await authorizeAblationTarget(peBinary, [tempDir]);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.format).toBe("pe");
    }
  });

  it("should detect unknown format for random bytes", async () => {
    const unknownBinary = join(tempDir, "test.unknown");
    writeFileSync(unknownBinary, Buffer.from([0xff, 0xff, 0xff]));

    const result = await authorizeAblationTarget(unknownBinary, [tempDir]);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.format).toBe("unknown");
    }
  });

  it("should reject when no approved roots provided", async () => {
    const result = await authorizeAblationTarget(testBinary, []);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisInputError");
    }
  });
});
