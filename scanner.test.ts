import { describe, expect, test } from "bun:test";
import { buildProbeBody, crashSignal, readResponseBody, versionVerdict } from "./scanner.ts";

const bytes = (value: string) => new TextEncoder().encode(value);
const response = (statusCode: number, body = "") => ({
  statusCode,
  body: bytes(body),
});

describe("version verdicts", () => {
  test("uses the configured fixed patch thresholds", () => {
    expect(versionVerdict("PHP/8.4.27")).toBe("FIXED");
    expect(versionVerdict("PHP/8.4.26")).toBe("VULNERABLE");
    expect(versionVerdict("PHP/8.5.12")).toBe("FIXED");
  });

  test("does not infer unsupported branches", () => {
    expect(versionVerdict("PHP/8.1.99")).toBeNull();
    expect(versionVerdict("Apache")).toBeNull();
  });
});

describe("probe construction", () => {
  test("matches the Python probe size and is deterministic", () => {
    const first = buildProbeBody(1, 4000);
    const second = buildProbeBody(1, 4000);
    expect(first.byteLength).toBe((1 << 20) - 1);
    expect(first).toBe(second);
    expect(new TextDecoder().decode(first.slice(-20))).not.toContain("\0");
  });
});

describe("crash signals", () => {
  test("detects the in-band fatal error with high confidence", () => {
    const signal = crashSignal(response(200, "ok"), response(500, "Allowed memory size of 1 bytes exhausted Unknown"), "auto");
    expect(signal?.signal).toBe("in_band_php_fatal");
    expect(signal?.confidence).toBe("high");
    expect(signal?.sapi).toBe("mod_php/PHP-FPM");
  });

  test("requires differential control output for an empty 500", () => {
    expect(crashSignal(response(200), response(500), "auto")).toBeNull();
    expect(crashSignal(response(200, "ok"), response(500), "auto")?.signal).toBe("empty_500_differential");
  });

  test("only enables gateway and empty-200 signals for FPM-capable modes", () => {
    expect(crashSignal(response(200, "ok"), response(502), "mod_php")).toBeNull();
    expect(crashSignal(response(200, "ok"), response(502), "auto")?.signal).toBe("fpm_gateway_error");
    expect(crashSignal(response(200, "ok"), response(200), "fpm")?.signal).toBe("empty_200_differential");
  });
});

test("retains at most one MiB while reading a response stream", async () => {
  const chunk = new Uint8Array(256 * 1024).fill(65);
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(chunk);
    },
  });
  const body = await readResponseBody(new Response(stream));
  expect(body.byteLength).toBe(1 << 20);
  expect(body[0]).toBe(65);
  expect(body[body.length - 1]).toBe(65);
});
