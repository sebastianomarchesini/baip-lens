import type { Analyzer } from '../types.js';
import { lockfileMissing } from './lockfileMissing.js';
import { notChecked } from './notChecked.js';

/**
 * Rules about the npm packages a project's lockfiles pin, in report order
 * (docs/rules.md). They require `collect.dependencies`, which a snapshot
 * written before lockfiles were read does not have, so they are kept apart
 * from the project rules, which need `collect.project` only.
 */
export const DEPENDENCY_ANALYZERS: readonly Analyzer[] = [lockfileMissing, notChecked];
