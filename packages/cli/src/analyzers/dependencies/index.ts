import type { Analyzer } from '../types.js';
import { knownCve } from './knownCve.js';
import { lockfileMissing } from './lockfileMissing.js';
import { notChecked } from './notChecked.js';

/**
 * Rules about the npm packages a project's lockfiles pin, in report order
 * (docs/rules.md): what is known about the packages first, then what could
 * not be said about them. They require `collect.dependencies`, which a
 * snapshot written before lockfiles were read does not have, so they are
 * kept apart from the project rules, which need `collect.project` only.
 * `DEP_KNOWN_CVE` also requires the lookup on OSV.dev (`collect.osv`): a
 * scan that was not handed one does not list the rule at all.
 */
export const DEPENDENCY_ANALYZERS: readonly Analyzer[] = [knownCve, lockfileMissing, notChecked];
