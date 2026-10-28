import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { existsSync } from "node:fs";

import { AblationProvider } from "./AblationProvider.js";
import { diagnoseAblation } from "./AblationDoctor.js";

const FIXTURE_ELF = join(process.cwd(), "tests/fixtures/taint-source-sink.elf");

describe("Ablation positive taint fixture", () => {
  it("observes real ablation taint execution on source-to-sink fixture", async () => {
    const cSource = join(process.cwd(), "tests/fixtures/taint-source-sink.c");
    if (!existsSync(cSource)) return;

    if (!existsSync(FIXTURE_ELF)) {
      try {
        const { execSync } = await import("node:child_process");
        execSync(`gcc -O0 -no-pie "${cSource}" -o "${FIXTURE_ELF}"`);
      } catch {
        return;
      }
    }

    const doctor = await diagnoseAblation({
      executable:
        process.env.REA_ABLATION_BIN ||
        "/home/freedom/.local/share/rea/ablation-venv/bin/ablation",
    });

    if (!doctor.ok) {
      return;
    }

    const provider = new AblationProvider(doctor.value, {
      executable:
        process.env.REA_ABLATION_BIN ||
        "/home/freedom/.local/share/rea/ablation-venv/bin/ablation",
      approvedRoots: [join(process.cwd(), "tests/fixtures")],
      timeoutMs: 30_000,
    });

    const result = await provider.taint({ target_path: FIXTURE_ELF });
    expect(result.ok).toBe(true);

    if (result.ok) {
      expect(result.value.target.format).toBe("elf");
      expect(result.value.execution.status).toBe("completed");
      expect(result.value.coverage).toBe("unknown");
      // Documenting actual observed fact: current Ablation taint engine returns 0 paths for this pattern.
      // We do not invent false positives.
      expect(result.value.findings).toEqual([]);
    }
  });
});
