import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";

import { createTestBinarySession } from "../../fixtures/binarySession.js";
import type { AblationObservationPort } from "../../../src/application/AblationObservationPort.js";
import type {
  AblationOperationObservation,
  AblationAnalyzeInput,
  AblationSearchInput,
  AblationTaintInput,
  AblationFunctionProfileInput,
} from "../../../src/domain/ablationObservation.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/toolContracts.js";

const fakeObservation: AblationOperationObservation = {
  operation: "analyze",
  target: {
    path: "/tmp/fixture.elf",
    sha256: "a".repeat(64),
    format: "elf",
    bytes: 1024,
  },
  execution: {
    exit_code: 0,
    duration_ms: 100,
    status: "completed",
  },
  provenance: {
    executable: "/usr/bin/ablation",
    version: "1.0.0",
    adapter_contract_version: 1,
  },
  raw_output: {
    stdout: '{"parsed": null}',
    stderr: "",
  },
  coverage: "partial",
  parsed: { sample: "result" },
  findings: [],
  limitations: ["Limited to static analysis"],
};

class FakeAblationProvider implements AblationObservationPort {
  identity() {
    return { id: "fake-ablation", name: "Fake Ablation", version: "1.0.0" };
  }

  async analyze(_input: AblationAnalyzeInput) {
    return ok({
      ...fakeObservation,
      operation: "analyze" as const,
    });
  }

  async search(_input: AblationSearchInput) {
    return ok({
      ...fakeObservation,
      operation: "search" as const,
    });
  }

  async taint(_input: AblationTaintInput) {
    return ok({
      ...fakeObservation,
      operation: "taint" as const,
    });
  }

  async profile(_input: AblationFunctionProfileInput) {
    return ok({
      ...fakeObservation,
      operation: "profile" as const,
    });
  }
}

it("discovers Ablation tools when provider is available", async () => {
  const session = createTestBinarySession(() => ({
    execute: () => Promise.resolve(observed(null)),
    close: () => Promise.resolve(),
  }));
  const server = createServer(session, session, {
    ablationObservation: new FakeAblationProvider(),
  });
  const client = new Client({
    name: "ablation-test",
    version: "1.0.0",
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const tools = await client.listTools();
  const ablationToolNames = tools.tools
    .filter(({ name }: { name: string }) => name.startsWith("ablation_"))
    .map(({ name }: { name: string }) => name);

  expect(ablationToolNames).toEqual([
    "ablation_analyze",
    "ablation_search",
    "ablation_taint",
    "ablation_function_profile",
  ]);

  await Promise.allSettled([client.close(), server.close(), session.close()]);
});

it("returns structured error when executing without provider", async () => {
  const session = createTestBinarySession(() => ({
    execute: () => Promise.resolve(observed(null)),
    close: () => Promise.resolve(),
  }));
  const server = createServer(session, session);
  const client = new Client({
    name: "ablation-test",
    version: "1.0.0",
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const result = await client.callTool({
    name: "ablation_analyze",
    arguments: {
      target_path: "/tmp/fixture.elf",
    },
  });

  expect(result.isError).toBe(true);

  await Promise.allSettled([client.close(), server.close(), session.close()]);
});

it("all Ablation contracts are registered in TOOL_CONTRACTS", () => {
  const ablationNames = [
    "ablation_analyze",
    "ablation_search",
    "ablation_taint",
    "ablation_function_profile",
  ];
  const registeredNames = TOOL_CONTRACTS.map(({ name }) => name);

  for (const name of ablationNames) {
    expect(registeredNames).toContain(name);
  }
});
