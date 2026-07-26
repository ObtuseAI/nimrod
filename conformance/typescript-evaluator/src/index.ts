import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync } from "node:fs";


type JsonPrimitive = boolean | null | number | string;
type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
interface JsonObject {
  [key: string]: JsonValue;
}

interface ThresholdVerification {
  readonly signerIds: readonly string[];
  readonly roles: readonly string[];
}

interface PolicyVerification {
  readonly digest: string;
  readonly origin: string;
  readonly evaluators: readonly JsonObject[];
}

interface IsolationVerification {
  readonly digest: string;
  readonly boundaryVerified: boolean;
  readonly productionEligible: boolean;
  readonly attestation: JsonObject;
}

interface LedgerVerification {
  readonly digest: string;
  readonly entryCount: number;
  readonly withinConstitution: boolean;
}

class ConformanceError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "ConformanceError";
  }
}


const POLICY_DOMAIN = Buffer.from("nimrod.evaluator-trust-policy.v0.1\0", "utf8");
const OBSERVATION_DOMAIN = Buffer.from("nimrod.evaluator-observation.v0.1\0", "utf8");
const ISOLATION_DOMAIN = Buffer.from("nimrod.os-isolation-attestation.v0.1\0", "utf8");
const LEDGER_DOMAIN = Buffer.from("nimrod.lineage-resource-ledger.v0.1\0", "utf8");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const REQUIRED_ROLES = new Set(["public_regression", "sealed_holdout", "adversarial", "rights_and_recovery"]);
const REQUIRED_CONTROLS = new Set([
  "CREDENTIAL_ISOLATION",
  "DEDICATED_OS_ACCOUNT",
  "DISTINCT_PROCESS",
  "EXECUTABLE_IDENTITY",
  "NETWORK_EGRESS_DENIED",
  "READ_ONLY_INPUT_ACL",
  "SEPARATE_OUTPUT_ACL",
]);
const POLICY_AUTHORITY: JsonObject = {
  can_select_itself: false,
  can_modify_constitution: false,
  can_grant_credentials: false,
  can_execute: false,
};
const OBSERVATION_AUTHORITY: JsonObject = {
  can_promote: false,
  can_execute: false,
  can_modify_evaluators: false,
  can_allocate_resources: false,
};
const ISOLATION_AUTHORITY: JsonObject = {
  can_authorize: false,
  can_execute: false,
  can_modify_acl: false,
  can_grant_credentials: false,
};
const LEDGER_AUTHORITY: JsonObject = {
  can_allocate: false,
  can_purchase_compute: false,
  can_extend_lease: false,
  can_execute: false,
};
const BUNDLE_AUTHORITY: JsonObject = {
  can_authorize: false,
  can_execute: false,
  can_promote: false,
};


function fail(code: string, message: string): never {
  throw new ConformanceError(code, message);
}


function requireObject(value: JsonValue | undefined, label: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("TYPE_OBJECT", `${label} must be an object.`);
  }
  return value as JsonObject;
}


function requireArray(value: JsonValue | undefined, label: string): JsonValue[] {
  if (!Array.isArray(value)) {
    fail("TYPE_ARRAY", `${label} must be an array.`);
  }
  return value;
}


function requireString(value: JsonValue | undefined, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    fail("TYPE_STRING", `${label} must be a non-empty string.`);
  }
  return value;
}


function requireInteger(value: JsonValue | undefined, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    fail("TYPE_INTEGER", `${label} must be a safe integer.`);
  }
  return value;
}


function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("CANONICAL_NUMBER", "Canonical JSON rejects non-finite numbers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item: JsonValue): string => canonicalJson(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort((left: string, right: string): number => left.localeCompare(right, "en"));
  return `{${keys.map((key: string): string => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`).join(",")}}`;
}


function sha256Digest(value: JsonValue): string {
  return `sha256:${createHash("sha256").update(Buffer.from(canonicalJson(value), "utf8")).digest("hex")}`;
}


function stripField(value: JsonObject, field: string): JsonObject {
  return Object.fromEntries(Object.entries(value).filter(([key]: [string, JsonValue]): boolean => key !== field));
}


function exactObject(value: JsonValue | undefined, expected: JsonObject, label: string): void {
  const actual = requireObject(value, label);
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail("AUTHORITY_WIDENED", `${label} exposes prohibited authority.`);
  }
}


function parseTime(value: JsonValue | undefined, label: string): number {
  const text = requireString(value, label);
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed)) {
    fail("TIME_INVALID", `${label} is not a valid timestamp.`);
  }
  return parsed;
}


function activeWindow(
  document: JsonObject,
  issuedField: string,
  nowMilliseconds: number,
  maximumLifetimeSeconds: number,
  label: string,
): number {
  const issued = parseTime(document[issuedField], `${label}.${issuedField}`);
  const notBefore = parseTime(document.not_before, `${label}.not_before`);
  const expires = parseTime(document.expires_at, `${label}.expires_at`);
  if (issued < notBefore || issued >= expires || nowMilliseconds < notBefore || nowMilliseconds >= expires) {
    fail("TIME_WINDOW", `${label} is outside its active validity window.`);
  }
  if ((expires - notBefore) / 1000 > maximumLifetimeSeconds) {
    fail("TIME_LIFETIME", `${label} exceeds its maximum lifetime.`);
  }
  return issued;
}


function decodeBase64(value: JsonValue | undefined, expectedLength: number, label: string): Buffer {
  const text = requireString(value, label);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    fail("BASE64_INVALID", `${label} is not canonical base64.`);
  }
  const decoded = Buffer.from(text, "base64");
  if (decoded.length !== expectedLength || decoded.toString("base64") !== text) {
    fail("BASE64_LENGTH", `${label} has an invalid decoded length or encoding.`);
  }
  return decoded;
}


function verifyEd25519(publicKeyBase64: JsonValue | undefined, signatureBase64: JsonValue | undefined, message: Buffer, label: string): void {
  const rawKey = decodeBase64(publicKeyBase64, 32, `${label}.public_key`);
  const signature = decodeBase64(signatureBase64, 64, `${label}.signature`);
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]), format: "der", type: "spki" });
  if (!verifySignature(null, message, key, signature)) {
    fail("SIGNATURE_INVALID", `${label} Ed25519 signature verification failed.`);
  }
}


function keyIndex(governance: JsonObject): Map<string, JsonObject> {
  const result = new Map<string, JsonObject>();
  for (const [index, value] of requireArray(governance.keys, "governance.keys").entries()) {
    const key = requireObject(value, `governance.keys[${index}]`);
    const keyId = requireString(key.key_id, `governance.keys[${index}].key_id`);
    if (result.has(keyId)) {
      fail("GOVERNANCE_DUPLICATE_KEY", `Governance repeats key '${keyId}'.`);
    }
    result.set(keyId, key);
  }
  return result;
}


function verifyThreshold(
  document: JsonObject,
  governance: JsonObject,
  issuedMilliseconds: number,
  domain: Buffer,
  label: string,
): ThresholdVerification {
  const signatures = requireArray(document.signatures, `${label}.signatures`);
  const keys = keyIndex(governance);
  const message = Buffer.concat([domain, Buffer.from(canonicalJson(stripField(document, "signatures")), "utf8")]);
  const signerIds = new Set<string>();
  const roles = new Set<string>();
  for (const [index, value] of signatures.entries()) {
    const signature = requireObject(value, `${label}.signatures[${index}]`);
    const signerId = requireString(signature.signer_id, `${label}.signatures[${index}].signer_id`);
    if (signerIds.has(signerId)) {
      fail("SIGNER_DUPLICATE", `${label} repeats signer '${signerId}'.`);
    }
    const key = keys.get(signerId);
    if (key === undefined) {
      fail("SIGNER_UNKNOWN", `${label} contains unknown signer '${signerId}'.`);
    }
    if (key.status !== "active" || key.algorithm !== "Ed25519") {
      fail("SIGNER_INACTIVE", `${label} signer '${signerId}' is not active Ed25519 material.`);
    }
    const validFrom = parseTime(key.valid_from, `${signerId}.valid_from`);
    const validUntil = key.valid_until === null ? null : parseTime(key.valid_until, `${signerId}.valid_until`);
    if (issuedMilliseconds < validFrom || (validUntil !== null && issuedMilliseconds >= validUntil)) {
      fail("SIGNER_TIME", `${label} signer '${signerId}' is inactive at issuance.`);
    }
    if (signature.algorithm !== "Ed25519") {
      fail("SIGNATURE_ALGORITHM", `${label} signer '${signerId}' does not use Ed25519.`);
    }
    verifyEd25519(key.public_key_base64, signature.signature_base64, message, `${label}:${signerId}`);
    signerIds.add(signerId);
    roles.add(requireString(key.role, `${signerId}.role`));
  }
  const threshold = requireInteger(governance.threshold, "governance.threshold");
  const minimumRoles = requireInteger(governance.minimum_distinct_roles, "governance.minimum_distinct_roles");
  if (signerIds.size < threshold || roles.size < minimumRoles) {
    fail("SIGNATURE_THRESHOLD", `${label} lacks the required signer threshold or role diversity.`);
  }
  return { signerIds: [...signerIds].sort(), roles: [...roles].sort() };
}


function verifyPolicy(
  policy: JsonObject,
  constitution: JsonObject,
  governance: JsonObject,
  nowMilliseconds: number,
  maximumLifetimeSeconds: number,
): PolicyVerification {
  if (policy.policy_version !== "0.1.0") {
    fail("POLICY_VERSION", "Evaluator trust policy version is unsupported.");
  }
  const issued = activeWindow(policy, "issued_at", nowMilliseconds, maximumLifetimeSeconds, "policy");
  const origin = requireString(policy.origin, "policy.origin");
  if (origin !== constitution.origin || origin !== governance.origin) {
    fail("POLICY_ORIGIN", "Evaluator policy origin differs from its roots.");
  }
  if (policy.constitution_digest !== sha256Digest(constitution) || policy.governance_state_digest !== sha256Digest(governance)) {
    fail("POLICY_ROOT_BINDING", "Evaluator policy root digest binding failed.");
  }
  exactObject(policy.authority, POLICY_AUTHORITY, "policy.authority");
  const evaluators = requireArray(policy.evaluators, "policy.evaluators").map(
    (value: JsonValue, index: number): JsonObject => requireObject(value, `policy.evaluators[${index}]`),
  );
  if (evaluators.length !== 4) {
    fail("EVALUATOR_COUNT", "Evaluator policy requires exactly four identities.");
  }
  const fields = ["evaluator_id", "logical_principal", "expected_os_account_identifier", "expected_os_account_sid", "role"];
  for (const field of fields) {
    const values = evaluators.map((evaluator: JsonObject): string => requireString(evaluator[field], `evaluator.${field}`).toLocaleLowerCase("en"));
    if (new Set(values).size !== values.length) {
      fail("EVALUATOR_IDENTITY_COLLAPSE", `Evaluator policy collapses '${field}'.`);
    }
  }
  const roles = new Set(evaluators.map((evaluator: JsonObject): string => requireString(evaluator.role, "evaluator.role")));
  if (roles.size !== REQUIRED_ROLES.size || [...roles].some((role: string): boolean => !REQUIRED_ROLES.has(role))) {
    fail("EVALUATOR_ROLE_SET", "Evaluator policy does not contain the constitutional role set.");
  }
  for (const evaluator of evaluators) {
    decodeBase64(evaluator.public_key_base64, 32, `evaluator:${String(evaluator.evaluator_id)}.public_key`);
  }
  verifyThreshold(policy, governance, issued, POLICY_DOMAIN, "evaluator policy");
  return { digest: sha256Digest(policy), origin, evaluators };
}


function verifyIsolation(
  attestation: JsonObject,
  governance: JsonObject,
  nowMilliseconds: number,
  maximumLifetimeSeconds: number,
): IsolationVerification {
  if (attestation.attestation_version !== "0.1.0") {
    fail("ISOLATION_VERSION", "Isolation attestation version is unsupported.");
  }
  const issued = activeWindow(attestation, "issued_at", nowMilliseconds, maximumLifetimeSeconds, "isolation attestation");
  if (attestation.governance_state_digest !== sha256Digest(governance)) {
    fail("ISOLATION_GOVERNANCE", "Isolation attestation governance binding failed.");
  }
  exactObject(attestation.authority, ISOLATION_AUTHORITY, "isolation.authority");
  const controls = requireArray(attestation.controls, "attestation.controls").map(
    (value: JsonValue, index: number): JsonObject => requireObject(value, `attestation.controls[${index}]`),
  );
  const ids = controls.map((control: JsonObject): string => requireString(control.control_id, "control.control_id"));
  if (new Set(ids).size !== REQUIRED_CONTROLS.size || ids.some((controlId: string): boolean => !REQUIRED_CONTROLS.has(controlId))) {
    fail("ISOLATION_CONTROL_SET", "Isolation attestation does not contain the exact seven-control set.");
  }
  const blockers = controls
    .filter((control: JsonObject): boolean => control.status !== "verified")
    .map((control: JsonObject): string => requireString(control.control_id, "control.control_id"))
    .sort();
  const violated = controls.some((control: JsonObject): boolean => control.status === "violated");
  const expectedStatus = blockers.length === 0 ? "verified" : violated ? "violated" : "boundary_unproven";
  if (attestation.status !== expectedStatus || canonicalJson(requireArray(attestation.blockers, "attestation.blockers")) !== canonicalJson(blockers)) {
    fail("ISOLATION_STATUS", "Isolation attestation status or blockers diverge from control evidence.");
  }
  for (const control of controls) {
    if (control.status === "verified" && requireArray(control.evidence, "control.evidence").length === 0) {
      fail("ISOLATION_EVIDENCE", "Verified isolation control lacks evidence.");
    }
  }
  verifyThreshold(attestation, governance, issued, ISOLATION_DOMAIN, "isolation attestation");
  const collector = requireObject(attestation.collector, "attestation.collector");
  const boundaryVerified = blockers.length === 0;
  const productionEligible = boundaryVerified && attestation.origin === "live" && collector.kind !== "fixture";
  return { digest: sha256Digest(attestation), boundaryVerified, productionEligible, attestation };
}


function verifyLedger(
  ledger: JsonObject,
  constitution: JsonObject,
  governance: JsonObject,
  nowMilliseconds: number,
  maximumLifetimeSeconds: number,
): LedgerVerification {
  if (ledger.ledger_version !== "0.1.0") {
    fail("LEDGER_VERSION", "Resource ledger version is unsupported.");
  }
  const generated = activeWindow(ledger, "generated_at", nowMilliseconds, maximumLifetimeSeconds, "resource ledger");
  if (ledger.constitution_digest !== sha256Digest(constitution) || ledger.governance_state_digest !== sha256Digest(governance)) {
    fail("LEDGER_ROOT_BINDING", "Resource ledger root binding failed.");
  }
  exactObject(ledger.authority, LEDGER_AUTHORITY, "ledger.authority");
  const entries = requireArray(ledger.entries, "ledger.entries").map(
    (value: JsonValue, index: number): JsonObject => requireObject(value, `ledger.entries[${index}]`),
  );
  if (entries.length === 0) {
    fail("LEDGER_EMPTY", "Resource ledger is empty.");
  }
  const ceilings = requireObject(constitution.resource_ceilings, "constitution.resource_ceilings");
  const seenDigests = new Set<string>();
  const seenIds = new Set<string>();
  const childCounts = new Map<string, number>();
  for (const [index, entry] of entries.entries()) {
    const candidateId = requireString(entry.candidate_id, `entries[${index}].candidate_id`);
    const candidateDigest = requireString(entry.candidate_digest, `entries[${index}].candidate_digest`);
    if (seenIds.has(candidateId) || seenDigests.has(candidateDigest)) {
      fail("LEDGER_IDENTITY_REPEAT", "Resource ledger repeats a candidate identity.");
    }
    if (index === 0 && entry.parent_candidate_digest !== null) {
      fail("LEDGER_ROOT_PARENT", "Resource ledger root has a parent.");
    }
    if (index > 0) {
      const parent = requireString(entry.parent_candidate_digest, `entries[${index}].parent_candidate_digest`);
      if (!seenDigests.has(parent)) {
        fail("LEDGER_FUTURE_PARENT", "Resource ledger references an absent or future parent.");
      }
      childCounts.set(parent, (childCounts.get(parent) ?? 0) + 1);
    }
    seenIds.add(candidateId);
    seenDigests.add(candidateDigest);
  }
  let previousDigest: string | null = null;
  let totalCycle = 0;
  let totalCompute = 0;
  let peakMemory = 0;
  let peakStorage = 0;
  const ledgerBlockers: string[] = [];
  for (const [index, entry] of entries.entries()) {
    if (requireInteger(entry.sequence, `entries[${index}].sequence`) !== index + 1 || entry.previous_entry_digest !== previousDigest) {
      fail("LEDGER_CHAIN", "Resource ledger sequence or predecessor digest is invalid.");
    }
    const lease = requireObject(entry.lease, `entries[${index}].lease`);
    const usage = requireObject(entry.usage, `entries[${index}].usage`);
    const pairs: readonly [string, string][] = [
      ["cycle_seconds", "maximum_cycle_seconds"],
      ["compute_units", "maximum_compute_units"],
      ["peak_memory_megabytes", "maximum_memory_megabytes"],
      ["peak_storage_megabytes", "maximum_storage_megabytes"],
    ];
    const blockers: string[] = [];
    for (const [usageField, leaseField] of pairs) {
      const leaseValue = requireInteger(lease[leaseField], `lease.${leaseField}`);
      const ceilingValue = requireInteger(ceilings[leaseField], `constitution.${leaseField}`);
      const usageValue = requireInteger(usage[usageField], `usage.${usageField}`);
      if (leaseValue > ceilingValue) {
        fail("LEDGER_CONSTITUTION_CEILING", `Ledger lease '${leaseField}' exceeds the Constitution.`);
      }
      if (usageValue > leaseValue) {
        blockers.push(`${usageField.toUpperCase()}_OVERRUN`);
      }
    }
    const candidateDigest = requireString(entry.candidate_digest, "entry.candidate_digest");
    const childCount = childCounts.get(candidateDigest) ?? 0;
    if (requireInteger(entry.child_count, "entry.child_count") !== childCount) {
      fail("LEDGER_CHILD_COUNT", "Ledger child count was substituted.");
    }
    if (childCount > requireInteger(lease.maximum_candidate_children, "lease.maximum_candidate_children")) {
      blockers.push("CANDIDATE_CHILDREN_OVERRUN");
    }
    blockers.sort();
    if (canonicalJson(requireArray(entry.blockers, "entry.blockers")) !== canonicalJson(blockers) || entry.status !== (blockers.length === 0 ? "within_lease" : "overrun")) {
      fail("LEDGER_ENTRY_STATUS", "Ledger entry status or blockers were substituted.");
    }
    ledgerBlockers.push(...blockers.map((code: string): string => `${code}:${String(entry.candidate_id)}`));
    totalCycle += requireInteger(usage.cycle_seconds, "usage.cycle_seconds");
    totalCompute += requireInteger(usage.compute_units, "usage.compute_units");
    peakMemory = Math.max(peakMemory, requireInteger(usage.peak_memory_megabytes, "usage.peak_memory_megabytes"));
    peakStorage = Math.max(peakStorage, requireInteger(usage.peak_storage_megabytes, "usage.peak_storage_megabytes"));
    previousDigest = sha256Digest(entry);
  }
  const expectedTotals: JsonObject = {
    total_cycle_seconds: totalCycle,
    total_compute_units: totalCompute,
    peak_memory_megabytes: peakMemory,
    peak_storage_megabytes: peakStorage,
    candidate_count: entries.length,
  };
  ledgerBlockers.sort();
  if (
    ledger.head_entry_digest !== previousDigest
    || canonicalJson(requireObject(ledger.totals, "ledger.totals")) !== canonicalJson(expectedTotals)
    || canonicalJson(requireArray(ledger.blockers, "ledger.blockers")) !== canonicalJson(ledgerBlockers)
    || ledger.status !== (ledgerBlockers.length === 0 ? "within_constitution" : "blocked")
  ) {
    fail("LEDGER_TOTALS", "Resource ledger head, totals, status, or blockers were substituted.");
  }
  verifyThreshold(ledger, governance, generated, LEDGER_DOMAIN, "resource ledger");
  return { digest: sha256Digest(ledger), entryCount: entries.length, withinConstitution: ledgerBlockers.length === 0 };
}


function policyEvaluator(policy: PolicyVerification, evaluatorId: string): JsonObject {
  const matches = policy.evaluators.filter((evaluator: JsonObject): boolean => evaluator.evaluator_id === evaluatorId);
  if (matches.length !== 1) {
    fail("EVALUATOR_NOT_TRUSTED", `Evaluator '${evaluatorId}' is not uniquely trusted.`);
  }
  return matches[0] as JsonObject;
}


function verifyEnvelope(
  envelope: JsonObject,
  policy: PolicyVerification,
  isolation: IsolationVerification,
  expected: JsonObject,
  nowMilliseconds: number,
): void {
  if (envelope.envelope_version !== "0.1.0") {
    fail("OBSERVATION_VERSION", "Evaluator observation version is unsupported.");
  }
  const observed = parseTime(envelope.observed_at, "envelope.observed_at");
  const expires = parseTime(envelope.expires_at, "envelope.expires_at");
  if (observed > nowMilliseconds || observed >= expires || nowMilliseconds >= expires) {
    fail("OBSERVATION_TIME", "Evaluator observation is future-dated or expired.");
  }
  const expectedBindings: JsonObject = {
    evaluator_policy_digest: policy.digest,
    subject_digest: expected.candidate_digest as JsonValue,
    constitution_digest: expected.constitution_digest as JsonValue,
    capability_report_digest: expected.capability_report_digest as JsonValue,
    evaluation_input_digest: expected.evaluation_input_digest as JsonValue,
    resource_ledger_digest: expected.resource_ledger_digest as JsonValue,
    isolation_attestation_digest: isolation.digest,
  };
  for (const [field, value] of Object.entries(expectedBindings)) {
    if (envelope[field] !== value) {
      fail("OBSERVATION_BINDING", `Evaluator observation binding '${field}' failed.`);
    }
  }
  if (!isolation.boundaryVerified) {
    fail("OBSERVATION_ISOLATION", "Evaluator observation lacks complete isolation contract evidence.");
  }
  const evaluatorId = requireString(envelope.evaluator_id, "envelope.evaluator_id");
  const trusted = policyEvaluator(policy, evaluatorId);
  const identityPairs: readonly [string, string][] = [
    ["role", "role"],
    ["logical_principal", "logical_principal"],
    ["os_account_identifier", "expected_os_account_identifier"],
    ["os_account_sid", "expected_os_account_sid"],
  ];
  for (const [envelopeField, policyField] of identityPairs) {
    if (envelope[envelopeField] !== trusted[policyField]) {
      fail("OBSERVATION_IDENTITY", `Evaluator observation identity '${envelopeField}' failed.`);
    }
  }
  const attestation = isolation.attestation;
  const process = requireObject(attestation.process, "attestation.process");
  if (
    attestation.component_kind !== "evaluator"
    || attestation.component_id !== evaluatorId
    || attestation.logical_principal !== envelope.logical_principal
    || process.process_id !== envelope.process_id
    || process.os_account_identifier !== envelope.os_account_identifier
    || process.os_account_sid !== envelope.os_account_sid
  ) {
    fail("OBSERVATION_ISOLATION_IDENTITY", "Evaluator observation and isolation identity diverge.");
  }
  if (!["pass", "fail", "inconclusive"].includes(requireString(envelope.status, "envelope.status"))) {
    fail("OBSERVATION_STATUS", "Evaluator observation status is unsupported.");
  }
  if (envelope.status === "pass" && requireArray(envelope.evidence, "envelope.evidence").length === 0) {
    fail("OBSERVATION_EVIDENCE", "Passing evaluator observation lacks evidence.");
  }
  exactObject(envelope.authority, OBSERVATION_AUTHORITY, "observation.authority");
  const signature = requireObject(envelope.signature, "envelope.signature");
  if (signature.signer_id !== evaluatorId || signature.algorithm !== "Ed25519") {
    fail("OBSERVATION_SIGNER", "Evaluator observation signer identity or algorithm failed.");
  }
  const message = Buffer.concat([OBSERVATION_DOMAIN, Buffer.from(canonicalJson(stripField(envelope, "signature")), "utf8")]);
  verifyEd25519(trusted.public_key_base64, signature.signature_base64, message, `observation:${evaluatorId}`);
}


function verifyBundle(bundle: JsonObject): JsonObject {
  if (bundle.bundle_version !== "0.1.0") {
    fail("BUNDLE_VERSION", "Conformance bundle version is unsupported.");
  }
  exactObject(bundle.authority, BUNDLE_AUTHORITY, "bundle.authority");
  const nowMilliseconds = parseTime(bundle.verification_time, "bundle.verification_time");
  const maximumLifetimeSeconds = requireInteger(bundle.maximum_lifetime_seconds, "bundle.maximum_lifetime_seconds");
  if (maximumLifetimeSeconds <= 0) {
    fail("BUNDLE_LIFETIME", "Conformance bundle maximum lifetime must be positive.");
  }
  const constitution = requireObject(bundle.constitution, "bundle.constitution");
  const governance = requireObject(bundle.governance_state, "bundle.governance_state");
  const policyDocument = requireObject(bundle.evaluator_policy, "bundle.evaluator_policy");
  const expected = requireObject(bundle.expected_bindings, "bundle.expected_bindings");
  const policy = verifyPolicy(policyDocument, constitution, governance, nowMilliseconds, maximumLifetimeSeconds);
  const ledgerDocument = requireObject(bundle.resource_ledger, "bundle.resource_ledger");
  const ledger = verifyLedger(ledgerDocument, constitution, governance, nowMilliseconds, maximumLifetimeSeconds);
  if (ledger.digest !== expected.resource_ledger_digest) {
    fail("BUNDLE_LEDGER_BINDING", "Conformance bundle expected resource ledger digest failed.");
  }
  const attestationDocuments = requireArray(bundle.isolation_attestations, "bundle.isolation_attestations").map(
    (value: JsonValue, index: number): JsonObject => requireObject(value, `bundle.isolation_attestations[${index}]`),
  );
  const envelopeDocuments = requireArray(bundle.evaluator_envelopes, "bundle.evaluator_envelopes").map(
    (value: JsonValue, index: number): JsonObject => requireObject(value, `bundle.evaluator_envelopes[${index}]`),
  );
  if (attestationDocuments.length !== 4 || envelopeDocuments.length !== 4) {
    fail("BUNDLE_EVALUATOR_COUNT", "Conformance bundle requires four attestations and four observations.");
  }
  const isolations = attestationDocuments.map(
    (attestation: JsonObject): IsolationVerification => verifyIsolation(attestation, governance, nowMilliseconds, maximumLifetimeSeconds),
  );
  const isolationByComponent = new Map<string, IsolationVerification>();
  for (const isolation of isolations) {
    const componentId = requireString(isolation.attestation.component_id, "attestation.component_id");
    if (isolationByComponent.has(componentId)) {
      fail("ISOLATION_IDENTITY_COLLAPSE", `Isolation attestation repeats component '${componentId}'.`);
    }
    isolationByComponent.set(componentId, isolation);
  }
  const envelopeIds = new Set<string>();
  const processIds = new Set<number>();
  for (const envelope of envelopeDocuments) {
    const evaluatorId = requireString(envelope.evaluator_id, "envelope.evaluator_id");
    const isolation = isolationByComponent.get(evaluatorId);
    if (isolation === undefined) {
      fail("OBSERVATION_ISOLATION_MISSING", `Evaluator '${evaluatorId}' lacks isolation evidence.`);
    }
    verifyEnvelope(envelope, policy, isolation, expected, nowMilliseconds);
    if (envelopeIds.has(evaluatorId)) {
      fail("OBSERVATION_IDENTITY_COLLAPSE", `Evaluator observation repeats '${evaluatorId}'.`);
    }
    const processId = requireInteger(envelope.process_id, "envelope.process_id");
    if (processIds.has(processId)) {
      fail("OBSERVATION_PROCESS_COLLAPSE", `Evaluator observations share process_id=${processId}.`);
    }
    envelopeIds.add(evaluatorId);
    processIds.add(processId);
  }
  if (envelopeIds.size !== 4 || policy.evaluators.some((evaluator: JsonObject): boolean => !envelopeIds.has(String(evaluator.evaluator_id)))) {
    fail("OBSERVATION_COMPLETENESS", "Evaluator observations do not cover the policy exactly.");
  }
  return {
    status: "TYPESCRIPT_EVALUATOR_CONFORMANCE_VALID",
    implementation: "typescript_node_crypto",
    shared_python_verification_logic: false,
    evaluator_count: envelopeIds.size,
    isolation_attestation_count: isolations.length,
    isolation_control_count_per_evaluator: REQUIRED_CONTROLS.size,
    resource_ledger_entry_count: ledger.entryCount,
    resource_ledger_within_constitution: ledger.withinConstitution,
    live_os_enforcement_verified: isolations.every((isolation: IsolationVerification): boolean => isolation.productionEligible),
    candidate_executed: false,
    production_promotion_authorized: false,
  };
}


function inputPath(argumentsList: readonly string[]): string {
  if (argumentsList.length !== 2 || argumentsList[0] !== "--input") {
    fail("CLI_ARGUMENTS", "Usage: node dist/index.js --input <conformance-bundle.json>");
  }
  return argumentsList[1] as string;
}


function main(): void {
  try {
    const path = inputPath(process.argv.slice(2));
    const parsed = JSON.parse(readFileSync(path, "utf8")) as JsonValue;
    const result = verifyBundle(requireObject(parsed, "bundle"));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error: unknown) {
    const code = error instanceof ConformanceError ? error.code : "UNEXPECTED_ERROR";
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${JSON.stringify({ status: "TYPESCRIPT_EVALUATOR_CONFORMANCE_REJECTED", code, message })}\n`);
    process.exitCode = 1;
  }
}


main();
