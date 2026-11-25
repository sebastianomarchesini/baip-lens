import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ConfigError } from '../../src/http/errors.js';
import { type CliIo, EXIT, main } from '../../src/main.js';
import { type Snapshot, SnapshotSchema } from '../../src/model/snapshot.js';
import type * as Project from '../../src/project.js';
import type * as ScanApp from '../../src/remote/scanApp.js';
import {
  MAX_SNAPSHOT_BYTES,
  SnapshotTooLargeError,
  loadableSnapshotText,
  readSnapshot,
  snapshotExcess,
  snapshotFileName,
  writeSnapshot,
  writeSnapshotText,
} from '../../src/snapshot.js';
import { readFixture } from '../support/snapshotText.js';

/*
 * `baip-lens project` checks the result of a scan against the limits
 * `readSnapshot` applies before it writes anything: a scan must never leave a
 * snapshot behind that `report --from` refuses. The limits are met here with
 * crafted results, because the collectors keep a real one far below them.
 */

/** What the two scans of `baip-lens project` return in the tests below: set per test. */
const scans = vi.hoisted((): { result: unknown } => ({ result: undefined }));

vi.mock('../../src/project.js', async (importOriginal) => ({
  ...(await importOriginal<typeof Project>()),
  scanProject: () => Promise.resolve(scans.result),
}));
vi.mock('../../src/remote/scanApp.js', async (importOriginal) => ({
  ...(await importOriginal<typeof ScanApp>()),
  scanApp: () => Promise.resolve(scans.result),
}));

const sample = (): Snapshot => SnapshotSchema.parse(readFixture('sample-project-snapshot.json'));

/** The sample with the evidence of its first finding replaced. */
function withEvidence(evidence: Record<string, unknown>): Snapshot {
  const snapshot = sample();
  const [first, ...rest] = snapshot.findings;
  if (first === undefined) throw new Error('the sample has no finding');
  return { ...snapshot, findings: [{ ...first, evidence }, ...rest] };
}

/** `depth` lists inside each other. */
function nested(depth: number): unknown {
  let value: unknown = 0;
  for (let i = 0; i < depth; i++) value = [value];
  return value;
}

const wide = (keys: number): Record<string, unknown> =>
  Object.fromEntries(Array.from({ length: keys }, (_, i) => [`k${i}`, 0]));

const ADVICE = 'Do less at a time.';

function refusal(snapshot: Snapshot): SnapshotTooLargeError {
  try {
    loadableSnapshotText(snapshot, ADVICE);
  } catch (error) {
    if (error instanceof SnapshotTooLargeError) return error;
    throw error;
  }
  throw new Error('the snapshot was accepted');
}

describe('loadableSnapshotText', () => {
  it('gives the text a scan writes, which reads back as the same snapshot', async () => {
    const snapshot = sample();
    const text = loadableSnapshotText(snapshot, ADVICE);
    expect(text).toBe(`${JSON.stringify(snapshot, null, 2)}\n`);
    const dir = await mkdtemp(join(tmpdir(), 'baip-lens-guard-'));
    const path = await writeSnapshotText(text, snapshot.scannedAt, join(dir, 'out'));
    expect(path).toBe(join(dir, 'out', snapshotFileName(snapshot.scannedAt)));
    expect(await readSnapshot(path)).toEqual(snapshot);
    // `baip-lens scan` writes the same bytes through the function it always used.
    const other = await writeSnapshot(snapshot, join(dir, 'scan'));
    expect(await readFile(other, 'utf8')).toBe(text);
  });

  it.each([
    ['an object with 1,000 keys', withEvidence(wide(1_000))],
    // The evidence is four levels deep itself: the snapshot, its findings, the finding, the evidence.
    ['lists nested to the 64th level', withEvidence({ deep: nested(60) })],
  ])('accepts %s', (_name, snapshot) => {
    expect(snapshotExcess(`${JSON.stringify(snapshot, null, 2)}\n`)).toBeUndefined();
    expect(() => loadableSnapshotText(snapshot, ADVICE)).not.toThrow();
  });

  it.each([
    [
      'an object with 1,001 keys',
      withEvidence(wide(1_001)),
      'members',
      'an object in it has more than 1,000 keys',
    ],
    [
      'lists nested to the 65th level',
      withEvidence({ deep: nested(61) }),
      'depth',
      'it nests more than 64 levels deep',
    ],
    [
      'more than 4,194,304 keys and values',
      withEvidence({ list: new Array<number>(4_200_000).fill(0) }),
      'items',
      'it holds more than 4,194,304 keys and values',
    ],
    [
      'more than 128 MiB',
      withEvidence({ text: 'x'.repeat(MAX_SNAPSHOT_BYTES) }),
      'bytes',
      'it is larger than 128 MiB',
    ],
  ])('refuses %s, as readSnapshot would', (_name, snapshot, excess, reason) => {
    const error = refusal(snapshot);
    expect(error).toBeInstanceOf(ConfigError);
    expect(error.excess).toBe(excess);
    expect(error.message).toBe(
      `The result of this scan cannot be written: ${reason}, and \`baip-lens report --from\` ` +
        'could not read it again. Nothing was written. Do less at a time.',
    );
  });

  it('refuses a result too long to be one text at all, by its size', () => {
    const endless = {
      ...sample(),
      toJSON(): never {
        throw new RangeError('Invalid string length');
      },
    };
    expect(refusal(endless).excess).toBe('bytes');
    // Any other error is not about the size and is not hidden.
    const broken = {
      ...sample(),
      toJSON(): never {
        throw new TypeError('boom');
      },
    };
    expect(() => loadableSnapshotText(broken, ADVICE)).toThrow(TypeError);
  });

  it('agrees with readSnapshot on a result just over a limit', async () => {
    const snapshot = withEvidence(wide(1_001));
    const dir = await mkdtemp(join(tmpdir(), 'baip-lens-guard-'));
    // Written unchecked, as `baip-lens scan` writes: this is what the check prevents.
    const path = await writeSnapshot(snapshot, dir);
    await expect(readSnapshot(path)).rejects.toThrow('an object in it has more than 1,000 keys');
  });
});

describe('baip-lens project and a result larger than a snapshot may be', () => {
  interface Captured {
    io: CliIo;
    out: () => string;
    err: () => string;
  }

  function capture(): Captured {
    let out = '';
    let err = '';
    return {
      io: {
        stdout: (text) => (out += text),
        stderr: (text) => (err += text),
        env: {},
        isTTY: false,
        fetch: () => Promise.reject(new Error('network must not be used')),
      },
      out: () => out,
      err: () => err,
    };
  }

  const MODES: [string, string[], string][] = [
    [
      '--path',
      ['--path', '.'],
      'Scan a part of the project at a time (--path <sub-folder>), or run it again with --no-dependency-check.',
    ],
    [
      '--cf',
      ['--cf', '--app', 'acme-srv'],
      'Read fewer apps at a time (--app <name>), or run it again with --no-dependency-check.',
    ],
  ];
  let out = '';
  beforeEach(async () => {
    out = join(await mkdtemp(join(tmpdir(), 'baip-lens-guard-out-')), 'reports');
  });
  const run = (mode: string[], c: Captured) =>
    main(['project', ...mode, '--out', out, '--format', 'json,csv,sarif'], c.io);

  it.each(MODES)(
    'with %s: ends with exit code 2, names the limit and what to do, and writes nothing',
    async (_name, mode, advice) => {
      scans.result = withEvidence(wide(1_001));
      const c = capture();
      expect(await run(mode, c)).toBe(EXIT.error);
      expect(c.err()).toBe(
        'baip-lens: The result of this scan cannot be written: an object in it has more than ' +
          '1,000 keys, and `baip-lens report --from` could not read it again. Nothing was written. ' +
          `${advice}\n`,
      );
      expect(c.out()).toBe('');
      // Neither the snapshot nor a report: not even the output folder.
      await expect(readdir(out)).rejects.toMatchObject({ code: 'ENOENT' });
    },
  );

  it.each(MODES)('with %s: writes a result within the limits as before', async (_name, mode) => {
    scans.result = sample();
    const c = capture();
    expect(await run(mode, c)).toBe(EXIT.ok);
    expect((await readdir(out)).sort()).toEqual([
      'baip-lens-apps.csv',
      'baip-lens-findings.csv',
      'baip-lens-report.json',
      'baip-lens-report.sarif',
      'snapshot-20260929T000000Z.json',
    ]);
    const written = await readSnapshot(join(out, 'snapshot-20260929T000000Z.json'));
    expect(written).toEqual(sample());
  });

  it.each(MODES)(
    'with %s: refuses a result that nests too deep or is too large',
    async (_name, mode) => {
      for (const [evidence, reason] of [
        [{ deep: nested(61) }, 'it nests more than 64 levels deep'],
        [
          { list: new Array<number>(4_200_000).fill(0) },
          'it holds more than 4,194,304 keys and values',
        ],
      ] as const) {
        scans.result = withEvidence(evidence);
        const c = capture();
        expect(await run(mode, c)).toBe(EXIT.error);
        expect(c.err()).toContain(`cannot be written: ${reason}, and`);
        await expect(readdir(out)).rejects.toMatchObject({ code: 'ENOENT' });
      }
    },
  );
});
