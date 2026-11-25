import { describe, expect, it } from 'vitest';
import { lockfileMissing } from '../../../src/analyzers/dependencies/lockfileMissing.js';
import { notChecked } from '../../../src/analyzers/dependencies/notChecked.js';
import {
  HIDDEN_LOCKFILE,
  MAX_LOCKFILES,
  SharedPackageBudget,
} from '../../../src/collectors/project/dependencies.js';
import {
  type CollectTreeOptions,
  MAX_FILES_OPENED,
  collectProjectTree,
} from '../../../src/collectors/project/index.js';
import { MAX_PACKAGES } from '../../../src/collectors/project/lockfile.js';
import { FindingSchema } from '../../../src/model/finding.js';
import type { RawProject } from '../../../src/model/raw.js';
import { RemoteSessionError, type RemoteStat } from '../../../src/remote/sftp.js';
import { APP_ROOT, SftpProjectTree } from '../../../src/remote/sftpTree.js';
import { hiddenLockfile, lockfileV3, registryEntry } from '../../support/lockfileFixture.js';
import { type MemoryEntry, MemorySftp, appFiles } from '../../support/memorySftp.js';
import { runRule } from '../../support/project.js';

/*
 * Which lockfiles a deployed app gets read (docs/data-sources.md §12.1): the
 * lockfile npm wrote into `node_modules` of the container when it is there
 * and can be used, else the root lockfile that was pushed, without its dev
 * entries. The container is a `MemorySftp`; package names are invented, and
 * `POISON` marks what must never come out.
 */

const HIDDEN_LOCATION = `${APP_ROOT}/${HIDDEN_LOCKFILE}`;
const ROOT_LOCK = `${APP_ROOT}/package-lock.json`;
const DEPLOYMENT = { app: 'acme-srv', mta: null };
const ZERO = {
  otherRegistry: 0,
  git: 0,
  file: 0,
  link: 0,
  bundled: 0,
  unknown: 0,
  excluded: 0,
  invalid: 0,
};

const MANIFEST = JSON.stringify({
  name: 'acme-srv',
  dependencies: { 'baip-server': '^2', '@POISON-scope/private': '^1' },
  devDependencies: { 'baip-test-kit': '^7' },
  optionalDependencies: { 'baip-watcher': '^2' },
  peerDependencies: { 'baip-peer': '*' },
});

const PRIVATE = {
  version: '1.0.0',
  resolved: 'https://npm.POISON.example.com/@POISON-scope/private/-/private-1.0.0.tgz',
  integrity: 'sha512-POISON_integrity',
};

/** What a production install left in the container: no dev package, and no flag that says so. */
const INSTALLED = hiddenLockfile('acme-srv', {
  'node_modules/baip-server': registryEntry('baip-server', '2.4.1'),
  'node_modules/baip-merge': registryEntry('baip-merge', '4.17.21'),
  'node_modules/baip-watcher': registryEntry('baip-watcher', '2.3.3', { optional: true }),
  'node_modules/baip-peer': { ...registryEntry('baip-peer', '1.0.0'), peer: true },
  'node_modules/@POISON-scope/private': PRIVATE,
});

/** What was pushed with the app: other versions than the ones installed, and the dev packages. */
const PUSHED = lockfileV3(
  {
    name: 'acme-srv',
    dependencies: { 'baip-server': '^2', '@POISON-scope/private': '^1' },
    devDependencies: { 'baip-test-kit': '^7' },
  },
  {
    'node_modules/baip-server': registryEntry('baip-server', '2.4.0'),
    'node_modules/baip-test-kit': registryEntry('baip-test-kit', '7.0.0', { dev: true }),
    'node_modules/baip-shared': registryEntry('baip-shared', '1.2.0', { devOptional: true }),
    'node_modules/@POISON-scope/private': PRIVATE,
    'node_modules/POISON-dev-private': { ...PRIVATE, dev: true },
  },
);

/** The lockfile of a module in a sub-folder: nothing is known about how it is installed. */
const ROUTER = lockfileV3(
  { name: 'acme-router', dependencies: { 'baip-router': '^1' } },
  {
    'node_modules/baip-router': registryEntry('baip-router', '1.0.0'),
    'node_modules/baip-router-test': registryEntry('baip-router-test', '1.1.0', { dev: true }),
  },
);

function container(files: Record<string, MemoryEntry>) {
  const sftp = new MemorySftp(appFiles({ 'package.json': MANIFEST, ...files }));
  sftp.maxAnswer = Infinity;
  return { sftp, tree: new SftpProjectTree(sftp, { rootName: 'acme-srv' }) };
}

/** Collects the container as `project --cf` does. */
function collect(tree: SftpProjectTree, options: CollectTreeOptions = {}): Promise<RawProject> {
  return collectProjectTree(tree, {
    id: 'acme-srv',
    deployment: DEPLOYMENT,
    hiddenLockfile: true,
    ...options,
  });
}

async function deployed(files: Record<string, MemoryEntry>, options: CollectTreeOptions = {}) {
  const { sftp, tree } = container(files);
  const project = await collect(tree, options);
  // Every file the collector opened is listed, as read or as unreadable.
  expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
  return { sftp, project, dependencies: project.dependencies! };
}

const opened = (sftp: MemorySftp): string[] =>
  sftp.requests.filter((r) => r.startsWith('open ')).map((r) => r.slice('open '.length));

/** Every request that names a path under `node_modules`, without the reads of the file. */
const underNodeModules = (sftp: MemorySftp): string[] =>
  sftp.requests.filter((r) => r.includes('node_modules') && !r.startsWith('read '));

const kept = (project: RawProject): string[] =>
  project.dependencies!.packages.map((item) => `${item.name}@${item.version} ${item.scope}`);

describe('the lockfile of the installed tree', () => {
  it('is asked for by its full path, read first as kind `hidden`, and answers for the root', async () => {
    const { sftp, project, dependencies } = await deployed({
      [HIDDEN_LOCKFILE]: INSTALLED,
      'package-lock.json': PUSHED,
      'app/router/package-lock.json': ROUTER,
      'node_modules/baip-server/package.json': '{"name":"POISON_installed_manifest"}',
      'node_modules/.bin/POISON': 'POISON',
    });
    expect(dependencies.lockfiles).toEqual([
      {
        file: 'app/router/package-lock.json',
        kind: 'package-lock',
        lockfileVersion: 3,
        status: 'read',
        kept: 2,
        notKept: ZERO,
      },
      {
        file: 'node_modules/.package-lock.json',
        kind: 'hidden',
        lockfileVersion: 3,
        status: 'read',
        kept: 4,
        notKept: { ...ZERO, otherRegistry: 1 },
      },
    ]);
    expect(dependencies.lockfilesNotRead).toBe(0);
    // Direct by the root package.json, in any of its four sections; the versions are the installed ones.
    expect(dependencies.packages).toEqual([
      {
        name: 'baip-merge',
        version: '4.17.21',
        direct: false,
        scope: 'prod',
        lockfiles: ['node_modules/.package-lock.json'],
      },
      {
        name: 'baip-peer',
        version: '1.0.0',
        direct: true,
        scope: 'prod',
        lockfiles: ['node_modules/.package-lock.json'],
      },
      {
        name: 'baip-router',
        version: '1.0.0',
        direct: true,
        scope: 'prod',
        lockfiles: ['app/router/package-lock.json'],
      },
      // A sub-folder lockfile is read as for a folder: its dev entries stay.
      {
        name: 'baip-router-test',
        version: '1.1.0',
        direct: false,
        scope: 'dev',
        lockfiles: ['app/router/package-lock.json'],
      },
      {
        name: 'baip-server',
        version: '2.4.1',
        direct: true,
        scope: 'prod',
        lockfiles: ['node_modules/.package-lock.json'],
      },
      {
        name: 'baip-watcher',
        version: '2.3.3',
        direct: true,
        scope: 'optional',
        lockfiles: ['node_modules/.package-lock.json'],
      },
    ]);

    // One look, one open, one close: nothing else under node_modules, which is never listed.
    expect(underNodeModules(sftp)).toEqual([
      `lstat ${HIDDEN_LOCATION}`,
      `open ${HIDDEN_LOCATION}`,
      `close ${HIDDEN_LOCATION}`,
    ]);
    // It is the first lockfile read; the root lockfile that was pushed is not opened at all.
    expect(opened(sftp).filter((path) => path.endsWith('lock.json'))).toEqual([
      HIDDEN_LOCATION,
      `${APP_ROOT}/app/router/package-lock.json`,
    ]);
    expect(sftp.requests.some((r) => r.endsWith(` ${ROOT_LOCK}`) && !r.startsWith('list'))).toBe(
      false,
    );

    expect(project.files).toEqual([
      'app/router/package-lock.json',
      'node_modules/.package-lock.json',
      'package.json',
    ]);
    expect(project.unreadable).toEqual([]);
    expect(project.filesOpened).toBe(3);
    expect(JSON.stringify(project.dependencies)).not.toContain('POISON');
  });

  it('leaves the pushed root lockfile without a record, whichever of the two names it has', async () => {
    const { sftp, dependencies } = await deployed({
      [HIDDEN_LOCKFILE]: INSTALLED,
      'package-lock.json': '{ POISON: not even JSON',
      'npm-shrinkwrap.json': PUSHED,
      'yarn.lock': '# POISON_yarn',
    });
    // The hidden lockfile, and the lockfile of another package manager, which is only listed.
    expect(dependencies.lockfiles.map((l) => [l.file, l.kind, l.status])).toEqual([
      ['node_modules/.package-lock.json', 'hidden', 'read'],
      ['yarn.lock', 'yarn', 'unsupported'],
    ]);
    // Left out on purpose, not for a limit: it is not counted as a lockfile that was not read.
    expect(dependencies.lockfilesNotRead).toBe(0);
    expect(opened(sftp)).toEqual([`${APP_ROOT}/package.json`, HIDDEN_LOCATION]);
    expect(dependencies.packages.map((item) => item.version)).not.toContain('2.4.0');
  });

  it('is found through a `node_modules` that is no directory in the listing, as on Cloud Foundry', async () => {
    // The listing shows a link, which the walk does not follow; the path of the file resolves
    // through it, as on a server.
    const { sftp, tree } = container({
      node_modules: { other: true },
      [HIDDEN_LOCKFILE]: INSTALLED,
    });
    const project = await collect(tree);
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.kind, l.status])).toEqual([
      ['node_modules/.package-lock.json', 'hidden', 'read'],
    ]);
    expect(sftp.requests.filter((r) => r.startsWith('list '))).toEqual([`list ${APP_ROOT}`]);
    expect(underNodeModules(sftp)).toEqual([
      `lstat ${HIDDEN_LOCATION}`,
      `open ${HIDDEN_LOCATION}`,
      `close ${HIDDEN_LOCATION}`,
    ]);
    // What the collector was shown of the app folder: `node_modules` is not a directory there.
    const listing = await sftp.list(APP_ROOT, 100);
    expect(listing.map((entry) => [entry.name, entry.type]).sort()).toEqual([
      ['node_modules', 'other'],
      ['package.json', 'file'],
    ]);
  });

  it('keeps its dev entries, public ones by name and others as a count: whatever it lists is installed', async () => {
    // A `node_modules` that was pushed with the app, or an install that did not leave them out.
    const { project, dependencies } = await deployed({
      [HIDDEN_LOCKFILE]: hiddenLockfile('acme-srv', {
        'node_modules/baip-server': registryEntry('baip-server', '2.4.1'),
        'node_modules/baip-test-kit': registryEntry('baip-test-kit', '7.0.0', { dev: true }),
        'node_modules/baip-mkdir': registryEntry('baip-mkdir', '0.5.1', { dev: true }),
        'node_modules/POISON-dev-private': { ...PRIVATE, dev: true },
      }),
    });
    expect(kept(project)).toEqual([
      'baip-mkdir@0.5.1 dev',
      'baip-server@2.4.1 prod',
      'baip-test-kit@7.0.0 dev',
    ]);
    expect(dependencies.lockfiles).toEqual([
      {
        file: 'node_modules/.package-lock.json',
        kind: 'hidden',
        lockfileVersion: 3,
        status: 'read',
        kept: 3,
        // The private dev package is installed too, so it is one that was not checked.
        notKept: { ...ZERO, otherRegistry: 1 },
      },
    ]);
    // Direct by the devDependencies of the root package.json.
    expect(dependencies.packages.map((item) => [item.name, item.direct])).toEqual([
      ['baip-mkdir', false],
      ['baip-server', true],
      ['baip-test-kit', true],
    ]);
    expect(JSON.stringify(dependencies)).not.toContain('POISON');

    // The same entries in the lockfile that was pushed are dropped: there they were only asked for.
    const pushed = await deployed({
      'package-lock.json': lockfileV3(
        { name: 'acme-srv', dependencies: { 'baip-server': '^2' } },
        {
          'node_modules/baip-server': registryEntry('baip-server', '2.4.1'),
          'node_modules/baip-test-kit': registryEntry('baip-test-kit', '7.0.0', { dev: true }),
          'node_modules/baip-mkdir': registryEntry('baip-mkdir', '0.5.1', { dev: true }),
          'node_modules/POISON-dev-private': { ...PRIVATE, dev: true },
        },
      ),
    });
    expect(kept(pushed.project)).toEqual(['baip-server@2.4.1 prod']);
    expect(pushed.dependencies.lockfiles[0]?.notKept).toEqual(ZERO);
  });

  it('is read even when the app already used up the files a scan opens', async () => {
    const models = Object.fromEntries(
      Array.from({ length: MAX_FILES_OPENED }, (_, i) => [
        `db/e${String(i).padStart(4, '0')}.cds`,
        'entity E {}',
      ]),
    );
    const { tree } = container({
      ...models,
      [HIDDEN_LOCKFILE]: INSTALLED,
      'app/router/package-lock.json': ROUTER,
    });
    const project = await collect(tree);
    // The other files stop at their limit: package.json and all but one of the models.
    expect(project.cdsFiles).toHaveLength(MAX_FILES_OPENED - 1);
    expect(project.filesTruncated).toBe(true);
    // The lockfiles have limits of their own, the hidden one too.
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.status])).toEqual([
      ['app/router/package-lock.json', 'read'],
      ['node_modules/.package-lock.json', 'read'],
    ]);
    expect(project.filesOpened).toBe(MAX_FILES_OPENED + 2);
    expect(runRule(lockfileMissing, project)).toEqual([]);
  });

  it('is not looked for unless the caller asks: a tree is read as a folder by default', async () => {
    const { sftp, tree } = container({
      [HIDDEN_LOCKFILE]: INSTALLED,
      'package-lock.json': PUSHED,
    });
    const project = await collectProjectTree(tree, { id: 'acme-srv', deployment: DEPLOYMENT });
    expect(sftp.requests.some((r) => r.includes('node_modules'))).toBe(false);
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.kind])).toEqual([
      ['package-lock.json', 'package-lock'],
    ]);
    // As for a folder: every entry of the pushed lockfile, the dev ones included.
    expect(kept(project)).toEqual([
      'baip-server@2.4.0 prod',
      'baip-shared@1.2.0 optional',
      'baip-test-kit@7.0.0 dev',
    ]);
    expect(project.dependencies?.lockfiles[0]?.notKept).toEqual({ ...ZERO, otherRegistry: 2 });
  });
});

describe('the fallback to the lockfile that was pushed', () => {
  it('costs one request when there is no hidden lockfile, which is neither opened nor unreadable', async () => {
    const { sftp, project, dependencies } = await deployed({
      'package-lock.json': PUSHED,
      'app/router/package-lock.json': ROUTER,
    });
    expect(underNodeModules(sftp)).toEqual([`lstat ${HIDDEN_LOCATION}`]);
    expect(project.unreadable).toEqual([]);
    expect(project.files).toEqual([
      'app/router/package-lock.json',
      'package-lock.json',
      'package.json',
    ]);
    expect(project.filesOpened).toBe(3);
    expect(dependencies.lockfiles.map((l) => [l.file, l.kind, l.status])).toEqual([
      ['app/router/package-lock.json', 'package-lock', 'read'],
      ['package-lock.json', 'package-lock', 'read'],
    ]);
  });

  it('drops the dev entries of the root lockfile: not installed, so neither kept nor counted', async () => {
    const { project, dependencies } = await deployed({
      'package-lock.json': PUSHED,
      'app/router/package-lock.json': ROUTER,
    });
    expect(kept(project)).toEqual([
      'baip-router@1.0.0 prod',
      // Of a sub-folder lockfile the dev entries stay.
      'baip-router-test@1.1.0 dev',
      'baip-server@2.4.0 prod',
      // devOptional: it may be installed.
      'baip-shared@1.2.0 optional',
    ]);
    const root = dependencies.lockfiles.find((l) => l.file === 'package-lock.json');
    // The private dev package is not among the "not checked" either; the private prod one is.
    expect(root).toMatchObject({ kept: 2, notKept: { ...ZERO, otherRegistry: 1 } });
    // Direct by the lockfile's own root entry.
    expect(dependencies.packages.find((item) => item.name === 'baip-server')?.direct).toBe(true);
    expect(JSON.stringify(dependencies)).not.toContain('POISON');
  });

  it('prefers npm-shrinkwrap.json over package-lock.json, as for a folder', async () => {
    const { sftp, dependencies } = await deployed({
      'package-lock.json': '{ POISON: the loser is not opened',
      'npm-shrinkwrap.json': PUSHED,
    });
    expect(dependencies.lockfiles.map((l) => [l.file, l.kind, l.status])).toEqual([
      ['npm-shrinkwrap.json', 'shrinkwrap', 'read'],
    ]);
    expect(opened(sftp)).not.toContain(ROOT_LOCK);
    expect(dependencies.packages.map((item) => item.name)).toEqual(['baip-server', 'baip-shared']);
  });

  it.each([
    ['is not JSON', '{ POISON: half a file', 'json'],
    ['looks binary', `{"lockfileVersion":3,\u0000"POISON":1}`, 'binary'],
    ['is no lockfile', '{"POISON":"neither packages nor a version 1 tree"}', 'json'],
  ] as const)(
    'is used when the hidden lockfile %s, whose record is kept',
    async (_what, text, kind) => {
      const { project, dependencies } = await deployed({
        [HIDDEN_LOCKFILE]: text,
        'package-lock.json': PUSHED,
      });
      expect(dependencies.lockfiles).toEqual([
        {
          file: 'node_modules/.package-lock.json',
          kind: 'hidden',
          lockfileVersion: null,
          status: 'unreadable',
          kept: 0,
          notKept: ZERO,
        },
        {
          file: 'package-lock.json',
          kind: 'package-lock',
          lockfileVersion: 3,
          status: 'read',
          kept: 2,
          notKept: { ...ZERO, otherRegistry: 1 },
        },
      ]);
      expect(project.unreadable).toEqual([{ file: 'node_modules/.package-lock.json', kind }]);
      expect(project.files).toEqual(['package-lock.json', 'package.json']);
      expect(kept(project)).toEqual(['baip-server@2.4.0 prod', 'baip-shared@1.2.0 optional']);
      expect(JSON.stringify(project)).not.toContain('POISON_');
    },
  );

  it('is used when the hidden lockfile changed between the look and the read', async () => {
    const { sftp, tree } = container({
      [HIDDEN_LOCKFILE]: INSTALLED,
      'package-lock.json': PUSHED,
    });
    // Swapped after it was probed: another modification time once it is opened.
    sftp.swapped.add(HIDDEN_LOCATION);
    const project = await collect(tree);
    expect(project.dependencies?.lockfiles.map((l) => [l.kind, l.status])).toEqual([
      ['hidden', 'unreadable'],
      ['package-lock', 'read'],
    ]);
    expect(project.unreadable).toEqual([{ file: 'node_modules/.package-lock.json', kind: 'json' }]);
    expect(sftp.requests).not.toContain(`read ${HIDDEN_LOCATION}`);
    expect(kept(project)).toEqual(['baip-server@2.4.0 prod', 'baip-shared@1.2.0 optional']);
  });

  it('is used when the packages of the hidden lockfile do not fit, and may fit itself', async () => {
    const { project, dependencies } = await deployed(
      { [HIDDEN_LOCKFILE]: INSTALLED, 'package-lock.json': PUSHED },
      { maxPackages: 2 },
    );
    expect(dependencies.lockfiles.map((l) => [l.kind, l.status, l.kept])).toEqual([
      ['hidden', 'too-many-packages', 0],
      ['package-lock', 'read', 2],
    ]);
    // It was read and parsed: listed as a file, not as an unreadable one.
    expect(project.files).toContain('node_modules/.package-lock.json');
    expect(project.unreadable).toEqual([]);
    expect(kept(project)).toEqual(['baip-server@2.4.0 prod', 'baip-shared@1.2.0 optional']);
  });

  it('takes a hidden lockfile that is no regular file (a link in the last place) as absent', async () => {
    const { sftp, project, dependencies } = await deployed({
      [HIDDEN_LOCKFILE]: { other: true },
      'package-lock.json': PUSHED,
    });
    expect(underNodeModules(sftp)).toEqual([`lstat ${HIDDEN_LOCATION}`]);
    expect(dependencies.lockfiles.map((l) => l.kind)).toEqual(['package-lock']);
    expect(project.unreadable).toEqual([]);
  });
});

describe('a session that is lost at the look for the hidden lockfile', () => {
  /** A container whose session goes with the first request that names a path under `node_modules`. */
  class LostAtTheLook extends MemorySftp {
    override lstat(path: string): Promise<RemoteStat> {
      if (path.includes('node_modules')) this.gone = true;
      return super.lstat(path);
    }
  }

  it.each([
    ['has no lockfile at all', {}],
    ['has the lockfile that was pushed', { 'package-lock.json': PUSHED }],
    ['has a lockfile in a sub-folder', { 'app/router/package-lock.json': ROUTER }],
  ] as [string, Record<string, MemoryEntry>][])(
    'ends the collection when the app %s: no answer is not "no hidden lockfile"',
    async (_what, files) => {
      const sftp = new LostAtTheLook(appFiles({ 'package.json': MANIFEST, ...files }));
      sftp.maxAnswer = Infinity;
      const tree = new SftpProjectTree(sftp, { rootName: 'acme-srv' });
      // Collected, such an app would be reported as one without a lockfile, or by the pushed one.
      await expect(collect(tree)).rejects.toBeInstanceOf(RemoteSessionError);
      // The look was the last request: no fallback and no other lockfile after a lost session.
      expect(sftp.requests.at(-1)).toBe(`lstat ${HIDDEN_LOCATION}`);
      expect(opened(sftp)).toEqual([`${APP_ROOT}/package.json`]);
    },
  );

  it('is told apart from a file that is not there, which is an answer', async () => {
    const { sftp, project } = await deployed({});
    expect(underNodeModules(sftp)).toEqual([`lstat ${HIDDEN_LOCATION}`]);
    expect(runRule(lockfileMissing, project).map((f) => f.evidence.cause)).toEqual(['none']);
  });
});

describe('the limit on lockfile records with a hidden lockfile', () => {
  const many = (count: number): Record<string, MemoryEntry> =>
    Object.fromEntries(
      Array.from({ length: count }, (_, i) => [
        `app/m${String(i).padStart(2, '0')}/package-lock.json`,
        lockfileV3(
          { name: 'module' },
          { 'node_modules/baip-shared': registryEntry('baip-shared', '1.2.0') },
        ),
      ]),
    );

  it(`keeps ${MAX_LOCKFILES} records with the hidden one among them, and counts the rest`, async () => {
    const read = await deployed({
      [HIDDEN_LOCKFILE]: INSTALLED,
      'package-lock.json': PUSHED,
      ...many(55),
    });
    expect(read.dependencies.lockfiles).toHaveLength(MAX_LOCKFILES);
    expect(read.dependencies.lockfiles.filter((l) => l.kind === 'hidden')).toHaveLength(1);
    // 55 lockfiles of sub-folders, 49 records left for them; the root one is not among the counted.
    expect(read.dependencies.lockfilesNotRead).toBe(6);

    const broken = await deployed({
      [HIDDEN_LOCKFILE]: '{',
      'package-lock.json': PUSHED,
      ...many(55),
    });
    expect(broken.dependencies.lockfiles).toHaveLength(MAX_LOCKFILES);
    expect(broken.dependencies.lockfiles.map((l) => l.file)).toContain('package-lock.json');
    expect(broken.dependencies.lockfilesNotRead).toBe(7);
  });
});

describe('DEP_LOCKFILE_MISSING and DEP_NOT_CHECKED on a deployed app', () => {
  it('reports an app without any root lockfile with cause `none` and the advice for a deployed app', async () => {
    const { project } = await deployed({ 'app/router/package-lock.json': ROUTER });
    const [finding] = runRule(lockfileMissing, project);
    expect(finding).toMatchObject({
      id: 'DEP_LOCKFILE_MISSING',
      severity: 'low',
      location: { file: 'package.json' },
    });
    expect(finding!.evidence).toMatchObject({
      subject: 'package.json',
      cause: 'none',
      // The two dependencies; the dev dependency of a deployed app is not installed.
      declaredDependencies: 2,
      lockfile: null,
      lockfileKind: null,
    });
    expect(finding!.remediation).toContain('Push the lockfile with the app');
    expect(finding!.remediation).not.toContain('commit');
  });

  it('reports nothing when the hidden lockfile was read, whether a lockfile was pushed or not', async () => {
    const alone = await deployed({ [HIDDEN_LOCKFILE]: INSTALLED });
    expect(runRule(lockfileMissing, alone.project)).toEqual([]);
    const both = await deployed({ [HIDDEN_LOCKFILE]: INSTALLED, 'package-lock.json': PUSHED });
    expect(runRule(lockfileMissing, both.project)).toEqual([]);
    // The private package of the installed tree is still said to be unchecked.
    expect(runRule(notChecked, both.project).map((f) => f.evidence)).toEqual([
      { subject: 'dependencies', ...ZERO, otherRegistry: 1, lockfilesNotRead: 0, checked: 4 },
    ]);
  });

  it('reports nothing for the root when the fallback was read, and counts the hidden lockfile as not read', async () => {
    const { project } = await deployed({ [HIDDEN_LOCKFILE]: '{', 'package-lock.json': PUSHED });
    expect(runRule(lockfileMissing, project)).toEqual([]);
    expect(runRule(notChecked, project).map((f) => f.evidence)).toEqual([
      { subject: 'dependencies', ...ZERO, otherRegistry: 1, lockfilesNotRead: 1, checked: 2 },
    ]);
  });

  it('points nowhere when the lockfile it is about is the hidden one', async () => {
    const { project } = await deployed({ [HIDDEN_LOCKFILE]: '{ POISON' });
    const [finding] = runRule(lockfileMissing, project);
    expect(finding!.evidence).toMatchObject({
      subject: 'node_modules/.package-lock.json',
      cause: 'unreadable',
      lockfile: 'node_modules/.package-lock.json',
      lockfileKind: 'hidden',
    });
    expect('location' in finding!).toBe(false);
    // Advice that can be followed for a file npm wrote in the container: no commit, no `--path`.
    expect(finding!.remediation).toContain('Restage the app');
    expect(finding!.remediation).not.toMatch(/commit|--path/);
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });
});

describe('the package budget the apps of one project run share', () => {
  const lock = (...names: string[]): string =>
    lockfileV3(
      { name: 'app' },
      Object.fromEntries(
        names.map((name) => [`node_modules/${name}`, registryEntry(name, '1.0.0')]),
      ),
    );
  const hidden = (...names: string[]): string =>
    hiddenLockfile(
      'app',
      Object.fromEntries(
        names.map((name) => [`node_modules/${name}`, registryEntry(name, '1.0.0')]),
      ),
    );

  it('starts at the limit of one scan and goes down by what each project kept, never below zero', () => {
    const budget = new SharedPackageBudget();
    expect(budget.remaining).toBe(MAX_PACKAGES);
    expect(MAX_PACKAGES).toBe(20_000);
    const keeping = (count: number) => ({
      dependencies: {
        lockfiles: [],
        lockfilesNotRead: 0,
        packages: Array.from({ length: count }, (_, i) => ({
          name: `p${i}`,
          version: '1.0.0',
          direct: false,
          scope: 'prod' as const,
          lockfiles: ['package-lock.json'],
        })),
      },
    });
    budget.spend(keeping(7));
    expect(budget.remaining).toBe(19_993);
    // A record written before lockfiles were read keeps nothing.
    budget.spend({ dependencies: null });
    expect(budget.remaining).toBe(19_993);

    const small = new SharedPackageBudget(5);
    small.spend(keeping(3));
    expect(small.remaining).toBe(2);
    small.spend(keeping(3));
    expect(small.remaining).toBe(0);
    // Never more than one scan may keep, whatever it is given.
    expect(new SharedPackageBudget(1e9).remaining).toBe(MAX_PACKAGES);
    expect(new SharedPackageBudget(-1).remaining).toBe(0);
  });

  it('gives each app what the apps before it left: a lockfile that does not fit is kept not at all', async () => {
    const budget = new SharedPackageBudget(4);
    const apps: Record<string, MemoryEntry>[] = [
      { [HIDDEN_LOCKFILE]: hidden('a', 'b', 'c') },
      // Two packages do not fit into the one that is left; the same package again costs one more.
      { [HIDDEN_LOCKFILE]: hidden('a', 'd'), 'srv/package-lock.json': lock('e') },
      { 'package-lock.json': lock('f') },
      // Nothing public to keep: such a lockfile is read even when nothing is left.
      {
        'package-lock.json': lockfileV3(
          { name: 'app' },
          { 'node_modules/@POISON-scope/private': PRIVATE },
        ),
      },
    ];
    const projects: RawProject[] = [];
    for (const files of apps) {
      const project = await collect(container(files).tree, { maxPackages: budget.remaining });
      budget.spend(project);
      projects.push(project);
    }
    const outcome = projects.map((project) => ({
      lockfiles: project.dependencies!.lockfiles.map((l) => `${l.file}: ${l.status}`),
      packages: project.dependencies!.packages.map((item) => item.name),
    }));
    expect(outcome).toEqual([
      { lockfiles: ['node_modules/.package-lock.json: read'], packages: ['a', 'b', 'c'] },
      {
        lockfiles: [
          'node_modules/.package-lock.json: too-many-packages',
          'srv/package-lock.json: read',
        ],
        packages: ['e'],
      },
      { lockfiles: ['package-lock.json: too-many-packages'], packages: [] },
      { lockfiles: ['package-lock.json: read'], packages: [] },
    ]);
    expect(budget.remaining).toBe(0);
    expect(projects.reduce((sum, p) => sum + p.dependencies!.packages.length, 0)).toBe(4);
    // The app whose lockfile did not fit is reported as one whose packages were not checked.
    expect(runRule(lockfileMissing, projects[2]!).map((f) => f.evidence.cause)).toEqual([
      'too-many-packages',
    ]);
    expect(runRule(notChecked, projects[2]!).map((f) => f.evidence.lockfilesNotRead)).toEqual([1]);
    // Both say what helps a deployed app: a run of that app alone, which has the whole budget.
    for (const rule of [lockfileMissing, notChecked]) {
      const [finding] = runRule(rule, projects[2]!);
      expect(finding!.remediation).toContain('`baip-lens project --cf --app <name>`');
    }
    // The finding about the lockfile itself does not send the reader to `--path`.
    expect(runRule(lockfileMissing, projects[2]!)[0]!.remediation).not.toContain('--path');
    // The sub-folder lockfile of the second app was read, so only its hidden one counts there.
    expect(runRule(lockfileMissing, projects[1]!).map((f) => f.evidence.cause)).toEqual([
      'too-many-packages',
    ]);
  });
});
