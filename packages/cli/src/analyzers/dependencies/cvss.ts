/*
 * The base score of a CVSS v3.0 or v3.1 vector, as the specification of
 * FIRST defines it (https://www.first.org/cvss/v3.1/specification-document,
 * section 7). An advisory of OSV.dev carries the vector, not the score, so
 * the rule `DEP_KNOWN_CVE` computes it here: from the snapshot alone, with
 * no request, the same again offline.
 *
 * Both versions share the weights and the formulas of the base score. They
 * differ in how a score is rounded up to one decimal: v3.0 says "round up"
 * and leaves the rest to the implementation, where floating-point arithmetic
 * made calculators disagree by 0.1 for some vectors; v3.1 defines the
 * rounding on integers so that they agree. That definition is used for both.
 */

const PREFIX = /^CVSS:3\.[01]$/;

type Weights = Readonly<Record<string, number>>;

const ATTACK_VECTOR: Weights = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const ATTACK_COMPLEXITY: Weights = { L: 0.77, H: 0.44 };
/** Privileges required weigh less against an attacker who can leave the scope of the component. */
const PRIVILEGES_REQUIRED: Record<'U' | 'C', Weights> = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
};
const USER_INTERACTION: Weights = { N: 0.85, R: 0.62 };
/** Confidentiality, integrity and availability share one scale. */
const IMPACT: Weights = { H: 0.56, L: 0.22, N: 0 };

/** The base metrics, each with the values it may take. A vector must name every one, once. */
const BASE_METRICS: Readonly<Record<string, readonly string[]>> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
};

const REQUIREMENT = ['X', 'H', 'M', 'L'];
/**
 * The temporal and environmental metrics. They do not change the base score,
 * but a vector that carries them is a valid vector, so they are checked and
 * then left aside. Each may appear once.
 */
const OTHER_METRICS: Readonly<Record<string, readonly string[]>> = {
  E: ['X', 'H', 'F', 'P', 'U'],
  RL: ['X', 'U', 'W', 'T', 'O'],
  RC: ['X', 'C', 'R', 'U'],
  CR: REQUIREMENT,
  IR: REQUIREMENT,
  AR: REQUIREMENT,
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'R'],
  MS: ['X', 'U', 'C'],
  MC: ['X', 'H', 'L', 'N'],
  MI: ['X', 'H', 'L', 'N'],
  MA: ['X', 'H', 'L', 'N'],
};

/**
 * The metrics of a vector by name, or undefined when it is not a CVSS v3
 * vector: another version, a metric that does not exist, a value a metric
 * cannot take, a metric named twice, or a base metric that is missing.
 * Because a metric may be named once, no text longer than the longest vector
 * (117 characters) gets through, whatever its length.
 */
function metricsOf(vector: string): ReadonlyMap<string, string> | undefined {
  const [prefix, ...parts] = vector.split('/');
  if (prefix === undefined || !PREFIX.test(prefix)) return undefined;
  const metrics = new Map<string, string>();
  for (const part of parts) {
    const separator = part.indexOf(':');
    const name = part.slice(0, Math.max(0, separator));
    const value = part.slice(separator + 1);
    // `Object.hasOwn`: a name such as `constructor` is not a metric.
    const allowed = Object.hasOwn(BASE_METRICS, name)
      ? BASE_METRICS[name]
      : Object.hasOwn(OTHER_METRICS, name)
        ? OTHER_METRICS[name]
        : undefined;
    if (allowed === undefined || !allowed.includes(value) || metrics.has(name)) return undefined;
    metrics.set(name, value);
  }
  return Object.keys(BASE_METRICS).every((name) => metrics.has(name)) ? metrics : undefined;
}

/**
 * "Roundup" of CVSS v3.1 (specification, appendix A): the smallest number
 * with one decimal that is not below `value`, computed on integers so that
 * 4.0 does not become 4.1 because it is held as 4.000000000000001.
 */
function roundUp(value: number): number {
  const scaled = Math.round(value * 100_000);
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10;
}

/**
 * The base score of a CVSS v3.0 or v3.1 vector, from 0.0 to 10.0 with one
 * decimal, or null when the text is not a valid vector of those versions.
 * Temporal and environmental metrics are allowed and do not change it.
 */
export function cvssV3BaseScore(vector: string): number | null {
  const metrics = metricsOf(vector);
  if (metrics === undefined) return null;
  // Every base metric is present with a value of its own scale: `metricsOf` checked it.
  const weight = (weights: Weights, name: string): number => weights[metrics.get(name) ?? ''] ?? 0;
  const changed = metrics.get('S') === 'C';
  const impactBase =
    1 - (1 - weight(IMPACT, 'C')) * (1 - weight(IMPACT, 'I')) * (1 - weight(IMPACT, 'A'));
  const impact = changed
    ? 7.52 * (impactBase - 0.029) - 3.25 * (impactBase - 0.02) ** 15
    : 6.42 * impactBase;
  if (impact <= 0) return 0;
  const exploitability =
    8.22 *
    weight(ATTACK_VECTOR, 'AV') *
    weight(ATTACK_COMPLEXITY, 'AC') *
    weight(PRIVILEGES_REQUIRED[changed ? 'C' : 'U'], 'PR') *
    weight(USER_INTERACTION, 'UI');
  return roundUp(
    Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10),
  );
}
