import { describe, it, expect, beforeEach } from "vitest";
import { AblationProvider, createAblationProvider } from "../ablation/index.js";
import type { ProviderIdentity } from "../application/AnalysisProvider.js";
import type { AblationRunPolicy } from "../domain/ablationObservation.js";
import { AnalysisCancelledError } from "../domain/errors.js";

describe("AblationProvider", () => {
  let provider: AblationProvider;
  let identity: ProviderIdentity;
  let policy: AblationRunPolicy;

  beforeEach(() => {
    identity = {
      id: "ablation",
      name: "Ablation",
      version: "1.0.0",
    };

    policy = {
      executable: "echo",
      approvedRoots: ["/usr/bin"],
      timeoutMs: 5000,
      maxOutputBytes: 2 * 1024 * 1024,
      allowModelDownload: false,
    };

    provider = new AblationProvider(identity, policy);
  });

  it("should return identity", () => {
    const id = provider.identity();
    expect(id).toEqual(identity);
  });

  it("should be created via factory", () => {
    const p = createAblationProvider(identity, policy);
    expect(p).toBeInstanceOf(AblationProvider);
    expect(p.identity()).toEqual(identity);
  });

  it("should reject early abort on analyze", async () => {
    const controller = new AbortController();
    controller.abort();

    const result = await provider.analyze(
      { target_path: "/usr/bin/ls" },
      { signal: controller.signal },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    }
  });

  it("should reject early abort on search", async () => {
    const controller = new AbortController();
    controller.abort();

    const result = await provider.search(
      { target_path: "/usr/bin/ls", query: "main" },
      { signal: controller.signal },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    }
  });

  it("should reject early abort on taint", async () => {
    const controller = new AbortController();
    controller.abort();

    const result = await provider.taint(
      { target_path: "/usr/bin/ls" },
      { signal: controller.signal },
    );

    expect(result.ok).toBe(false);
  });

  it("should reject early abort on profile", async () => {
    const controller = new AbortController();
    controller.abort();

    const result = await provider.profile(
      { target_path: "/usr/bin/ls", address: "0x401000" },
      { signal: controller.signal },
    );

    expect(result.ok).toBe(false);
  });
});
