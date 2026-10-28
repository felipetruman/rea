import {
  createReadStream,
  statSync,
  openSync,
  readSync,
  closeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { relative } from "node:path";
import { realpath } from "node:fs/promises";
import type { AblationTargetRef } from "../domain/ablationObservation.js";
import { ABLATION_MAX_TARGET_PATH_CHARACTERS } from "../domain/ablationObservation.js";
import type { AnalysisError } from "../domain/errors.js";
import { AnalysisInputError } from "../domain/errors.js";
import type { Result } from "../domain/result.js";
import { err, ok } from "../domain/result.js";

/** Detect binary format from magic bytes. */
function detectFormat(magicBytes: Buffer): "elf" | "pe" | "mach-o" | "unknown" {
  if (magicBytes.length < 2) return "unknown";

  // PE: 0x4d 0x5a (MZ)
  if (magicBytes[0] === 0x4d && magicBytes[1] === 0x5a) {
    return "pe";
  }

  if (magicBytes.length < 4) return "unknown";

  // ELF: 0x7f 0x45 0x4c 0x46
  if (
    magicBytes[0] === 0x7f &&
    magicBytes[1] === 0x45 &&
    magicBytes[2] === 0x4c &&
    magicBytes[3] === 0x46
  ) {
    return "elf";
  }

  // Mach-O: 0xfe 0xed 0xfa (32-bit), 0xfe 0xed 0xfa 0xce/0xcf (64-bit), 0xfe 0xed 0xfa 0xed (FAT)
  if (
    magicBytes[0] === 0xfe &&
    magicBytes[1] === 0xed &&
    magicBytes[2] === 0xfa
  ) {
    return "mach-o";
  }

  return "unknown";
}

/**
 * Authorize and digest a target path for Ablation analysis.
 * Validates against approved roots, resolves canonical paths, blocks symlink escapes,
 * detects binary format, and computes SHA-256.
 */
// oxlint-disable-next-line max-lines-per-function
export async function authorizeAblationTarget(
  targetPath: string,
  approvedRoots: readonly string[],
): Promise<Result<AblationTargetRef, AnalysisError>> {
  // Validate input
  if (!targetPath || targetPath.length > ABLATION_MAX_TARGET_PATH_CHARACTERS) {
    return err(
      new AnalysisInputError("ablation:authorize", undefined, [
        {
          path: ["target_path"],
          reason:
            targetPath.length > ABLATION_MAX_TARGET_PATH_CHARACTERS
              ? "out_of_range"
              : "missing_argument",
          message: "Target path required and must be < 4096 characters",
        },
      ]),
    );
  }

  if (approvedRoots.length === 0) {
    return err(
      new AnalysisInputError("ablation:authorize", undefined, [
        {
          path: ["approved_roots"],
          reason: "missing_argument",
          message: "No approved input roots configured",
        },
      ]),
    );
  }

  try {
    // Resolve canonical paths
    const resolvedTarget = await realpath(targetPath);
    const resolvedRoots = await Promise.all(
      approvedRoots.map((r) => realpath(r)),
    );

    // Check if target is inside one of the approved roots
    let authorized = false;
    for (const root of resolvedRoots) {
      const rel = relative(root, resolvedTarget);
      // Relative path starting with .. or being absolute means outside root
      if (!rel.startsWith("..") && !rel.startsWith("/")) {
        authorized = true;
        break;
      }
    }

    if (!authorized) {
      return err(
        new AnalysisInputError("ablation:authorize", undefined, [
          {
            path: ["target_path"],
            reason: "invalid_value",
            message: `Target path not within approved input roots`,
          },
        ]),
      );
    }

    // Stat and validate it's a file (not directory)
    const stats = statSync(resolvedTarget);
    if (!stats.isFile()) {
      return err(
        new AnalysisInputError("ablation:authorize", undefined, [
          {
            path: ["target_path"],
            reason: "invalid_value",
            message: "Target must be a file, not a directory",
          },
        ]),
      );
    }

    // Read magic bytes for format detection
    const magicBuffer = Buffer.alloc(4);
    const fd = openSync(resolvedTarget, "r");
    let bytesRead = 0;
    try {
      bytesRead = readSync(fd, magicBuffer, 0, 4, 0);
    } finally {
      closeSync(fd);
    }

    const format = detectFormat(magicBuffer.subarray(0, bytesRead));

    // Compute SHA-256
    const hash = createHash("sha256");
    const stream = createReadStream(resolvedTarget);
    await new Promise<void>((streamResolve, streamReject) => {
      stream.on("data", (chunk) => hash.update(chunk));
      stream.on("end", () => streamResolve());
      stream.on("error", streamReject);
    });

    return ok({
      path: resolvedTarget,
      sha256: hash.digest("hex"),
      format,
      bytes: stats.size,
    });
  } catch (thrown) {
    const cause = thrown instanceof Error ? thrown : new Error(String(thrown));
    const message =
      cause.message.includes("ENOENT") || cause.message.includes("EACCES")
        ? `Cannot access target path: ${cause.message}`
        : `Failed to authorize target: ${cause.message}`;

    return err(
      new AnalysisInputError("ablation:authorize", { cause }, [
        {
          path: ["target_path"],
          reason: "invalid_value",
          message,
        },
      ]),
    );
  }
}
