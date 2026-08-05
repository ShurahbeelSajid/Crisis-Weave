import http from "k6/http";
import { check, sleep } from "k6";
import { Rate } from "k6/metrics";

export const options = {
  stages: [
    { duration: "30s", target: 10 },
    { duration: "60s", target: 10 },
    { duration: "30s", target: 0 },
  ],
  thresholds: {
    checks: ["rate==1"],
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<10000"],
    quality_gate_passed: ["rate==1"],
  },
};

const apiUrl = (__ENV.CRISISWEAVE_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
const apiKey = __ENV.CRISISWEAVE_API_KEY;
const seedFilename = "cw_eval_field_report.txt";
const expectedToken = "ORCHID-FALCON-731";
const seedBody = open("../evals/fixtures/cw_eval_field_report.txt", "b");
const qualityGatePassed = new Rate("quality_gate_passed");

function parseObject(response) {
  try {
    const body = response.json();
    return body !== null && typeof body === "object" && !Array.isArray(body) ? body : null;
  } catch (_) {
    return null;
  }
}

function citationsAreValid(body) {
  if (
    typeof body.answer !== "string" ||
    !Array.isArray(body.evidence) ||
    !Array.isArray(body.citations) ||
    body.citations.length === 0
  ) {
    return false;
  }
  const labels = new Set();
  const evidenceIds = new Set();
  for (const citation of body.citations) {
    const match =
      typeof citation.label === "string" ? /^E([1-9]|[12]\d|30)$/.exec(citation.label) : null;
    if (match === null || labels.has(citation.label) || evidenceIds.has(citation.evidence_id)) {
      return false;
    }
    const evidence = body.evidence[Number(match[1]) - 1];
    if (
      evidence === undefined ||
      citation.evidence_id !== evidence.id ||
      citation.source_name !== evidence.source_name ||
      citation.source_uri !== evidence.source_uri ||
      citation.page !== evidence.page ||
      citation.timestamp_seconds !== evidence.timestamp_seconds ||
      !body.answer.includes(`[${citation.label}]`)
    ) {
      return false;
    }
    labels.add(citation.label);
    evidenceIds.add(citation.evidence_id);
  }
  const rawTokens = body.answer.match(/\[[eE][^\]\r\n]*\]/g) || [];
  const answerLabels = new Set();
  for (const token of rawTokens) {
    const match = /^\[E([1-9]|[12]\d|30)\]$/.exec(token);
    if (match === null) {
      return false;
    }
    answerLabels.add(`E${match[1]}`);
  }
  return answerLabels.size === labels.size && [...answerLabels].every((label) => labels.has(label));
}

export function setup() {
  if (!apiKey) {
    throw new Error("CRISISWEAVE_API_KEY is required");
  }
  const response = http.post(
    `${apiUrl}/v1/documents`,
    { file: http.file(seedBody, seedFilename, "text/plain") },
    { headers: { "X-API-Key": apiKey } },
  );
  const body = parseObject(response);
  const ready =
    response.status === 201 &&
    body !== null &&
    body.document !== null &&
    typeof body.document === "object" &&
    body.document.filename === seedFilename &&
    typeof body.document.id === "string" &&
    body.document.id.length > 0 &&
    body.document.status === "ready" &&
    Number.isInteger(body.document.chunk_count) &&
    body.document.chunk_count > 0 &&
    typeof body.deduplicated === "boolean";
  check(response, { "deterministic seed is ready": () => ready });
  if (!ready) {
    throw new Error(`deterministic seed failed with HTTP ${response.status}`);
  }
  return {
    documentId: body.document.id,
    deleteOnTeardown: !body.deduplicated,
  };
}

export default function () {
  const response = http.post(
    `${apiUrl}/v1/query`,
    JSON.stringify({
      query: "What call sign and containment percentage were recorded for Cedar Ridge?",
      allow_web: false,
      top_k: 6,
    }),
    { headers: { "Content-Type": "application/json", "X-API-Key": apiKey } },
  );
  const body = parseObject(response);
  const routesAreExact =
    body !== null &&
    Array.isArray(body.routes) &&
    body.routes.length === 1 &&
    body.routes[0] === "vector";
  const seedEvidence =
    body !== null &&
    Array.isArray(body.evidence) &&
    body.evidence.find(
      (item) =>
        item.source_name === seedFilename &&
        typeof item.excerpt === "string" &&
        item.excerpt.includes(expectedToken) &&
        item.excerpt.includes("37 percent"),
    );
  const seedCitation =
    body !== null &&
    Array.isArray(body.citations) &&
    body.citations.some((item) => item.source_name === seedFilename);
  const vectorTrace =
    body !== null &&
    Array.isArray(body.tool_trace) &&
    body.tool_trace.length === 1 &&
    body.tool_trace[0].tool === "vector" &&
    body.tool_trace[0].status === "ok" &&
    body.tool_trace[0].result_count > 0;
  const groundedAnswer =
    body !== null &&
    typeof body.answer === "string" &&
    body.answer.includes(expectedToken) &&
    body.answer.includes("37 percent") &&
    !body.answer.toLowerCase().includes("do not have enough authorized evidence") &&
    !body.answer.toLowerCase().includes("withholding the answer");
  const qualityOk =
    response.status === 200 &&
    routesAreExact &&
    Boolean(seedEvidence) &&
    seedCitation &&
    vectorTrace &&
    groundedAnswer &&
    citationsAreValid(body);

  qualityGatePassed.add(qualityOk);
  check(response, {
    "query status is 200": (result) => result.status === 200,
    "route is exactly vector": () => routesAreExact,
    "seed evidence and facts are returned": () => Boolean(seedEvidence),
    "seed source is cited": () => seedCitation,
    "citation mapping is valid": () => body !== null && citationsAreValid(body),
    "vector tool returned evidence": () => vectorTrace,
    "answer is grounded and does not abstain": () => groundedAnswer,
  });
  sleep(1);
}

export function teardown(data) {
  if (data === undefined || !data.deleteOnTeardown) {
    return;
  }
  const response = http.del(`${apiUrl}/v1/documents/${data.documentId}`, null, {
    headers: { "X-API-Key": apiKey },
  });
  if (response.status !== 204) {
    throw new Error(`seed cleanup failed with HTTP ${response.status}`);
  }
}
