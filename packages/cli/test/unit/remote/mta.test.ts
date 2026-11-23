import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { PROJECT_ID_PATTERN } from '../../../src/model/raw.js';
import {
  MAX_PROJECT_APPS,
  type MtaApp,
  type MtaMetadata,
  MtaMetadataSchema,
  UNUSABLE_NAMESPACE,
  deploymentName,
  groupByMta,
  hashedLabel,
  mtaIdentity,
  overAppLimit,
  overAppLimitWhy,
  projectIdOf,
  projectLabel,
  projectTitle,
  projectVersion,
  withProjectIds,
} from '../../../src/remote/mta.js';
import { CfAppSchema } from '../../../src/remote/selectApps.js';

/*
 * The MTA picker's pure parts: which of an app's labels and annotations are
 * read, which apps count as one project, how the picker words a project, and
 * the project id an app is reported under. The values come from whoever may
 * update an app, so most cases here are about what must not get through.
 */

const md5 = (text: string): string => createHash('md5').update(text, 'utf8').digest('hex');

/** The labels and annotations the deploy service writes for one module of an MTA. */
function deployed(
  id: string,
  options: { version?: string; module?: string; namespace?: string } = {},
): { labels: Record<string, string>; annotations: Record<string, string> } {
  const { version = '1.0.0', module, namespace } = options;
  return {
    labels: {
      mta_id: md5(id),
      ...(namespace === undefined ? {} : { mta_namespace: md5(namespace) }),
    },
    annotations: {
      mta_id: id,
      mta_version: version,
      ...(module === undefined ? {} : { mta_module: JSON.stringify({ name: module }) }),
      ...(namespace === undefined ? {} : { mta_namespace: namespace }),
    },
  };
}

const parse = (metadata: unknown): MtaMetadata => MtaMetadataSchema.parse(metadata);

const app = (name: string, metadata?: unknown): MtaApp => ({ name, metadata: parse(metadata) });

const names = (apps: readonly MtaApp[]): string[] => apps.map((a) => a.name);

describe('the MTA metadata of an app', () => {
  it('keeps the six keys the deploy service writes, the module as its name', () => {
    const metadata = parse(
      deployed('acme.incidents', { version: '1.2.0', module: 'incidents-srv', namespace: 'blue' }),
    );
    expect(metadata).toEqual({
      labels: { mta_id: md5('acme.incidents'), mta_namespace: md5('blue') },
      annotations: {
        mta_id: 'acme.incidents',
        mta_version: '1.2.0',
        mta_namespace: 'blue',
        mta_module: 'incidents-srv',
      },
    });
  });

  it('drops every other label and annotation, a planted e-mail included', () => {
    const source = deployed('acme');
    const metadata = parse({
      labels: { ...source.labels, team: 'payments' },
      annotations: {
        ...source.annotations,
        contact: 'owner@example.com',
        mta_bound_services: '["acme-db","acme-uaa"]',
        mta_module_provided_dependencies: '["srv-api"]',
      },
      owner: 'owner@example.com',
    });
    expect(JSON.stringify(metadata)).not.toContain('example.com');
    expect(Object.keys(metadata)).toEqual(['labels', 'annotations']);
    expect(Object.keys(metadata.labels)).toEqual(['mta_id']);
    expect(Object.keys(metadata.annotations).sort()).toEqual(['mta_id', 'mta_version']);
  });

  it.each([
    ['missing', undefined],
    ['null', null],
    ['a string', 'metadata'],
    ['an array', [1, 2]],
    ['a number', 7],
    ['null labels and annotations', { labels: null, annotations: null }],
    ['labels and annotations of the wrong type', { labels: 'x', annotations: ['mta_id'] }],
  ])('reads %s metadata as no metadata', (_name, metadata) => {
    expect(parse(metadata)).toEqual({ labels: {}, annotations: {} });
  });

  it('leaves out a key of the wrong type or null, and keeps the keys next to it', () => {
    const metadata = parse({
      labels: { mta_id: 42, mta_namespace: md5('blue') },
      annotations: { mta_id: null, mta_version: '2.0.0', mta_namespace: {}, mta_module: 5 },
    });
    expect(metadata.labels).toEqual({ mta_namespace: md5('blue') });
    // A namespace key that is there but cannot be used is marked, not left out.
    expect(metadata.annotations).toEqual({
      mta_version: '2.0.0',
      mta_namespace: UNUSABLE_NAMESPACE,
    });
  });

  it.each([
    ['a control character', 'acme\u001b[31m'],
    ['a trailing newline', 'acme\n'],
    ['a space', 'acme incidents'],
    ['a slash', 'acme/incidents'],
    ['markup', '<b>acme</b>'],
    ['6000 characters', 'a'.repeat(6000)],
    ['129 characters', 'a'.repeat(129)],
    ['an empty string', ''],
  ])('leaves out an mta_id annotation with %s', (_name, value) => {
    const metadata = parse({ labels: { mta_id: md5(value) }, annotations: { mta_id: value } });
    expect(metadata.annotations).toEqual({});
    expect(mtaIdentity(metadata)).toBeNull();
  });

  it('leaves out a version that does not match its pattern, and keeps of such a namespace only that it is there', () => {
    const annotations = parse({
      annotations: {
        mta_version: '1.0.0 (hotfix)',
        mta_namespace: 'n'.repeat(37),
      },
    }).annotations;
    expect(annotations).toEqual({ mta_namespace: UNUSABLE_NAMESPACE });
    expect(parse({ annotations: { mta_version: 'v'.repeat(65) } }).annotations).toEqual({});
    expect(parse({ annotations: { mta_namespace: 'n'.repeat(36) } }).annotations).toEqual({
      mta_namespace: 'n'.repeat(36),
    });
  });

  it('reads only its own keys from a body with a __proto__ key', () => {
    const body: unknown = JSON.parse(
      `{"labels":{"__proto__":{"mta_id":"${md5('acme')}"}},"annotations":{"__proto__":{"mta_id":"acme"},"constructor":"x"}}`,
    );
    expect(parse(body)).toEqual({ labels: {}, annotations: {} });
    expect(({} as Record<string, unknown>).mta_id).toBeUndefined();
  });

  it.each([
    ['valid', '{"name":"incidents-srv"}', 'incidents-srv'],
    ['valid with other keys', '{"name":"srv","path":"gen/srv"}', 'srv'],
    ['not JSON', '{name: srv}', undefined],
    ['a JSON string', '"srv"', undefined],
    ['a JSON array', '[{"name":"srv"}]', undefined],
    ['null', 'null', undefined],
    ['without a name', '{"module":"srv"}', undefined],
    ['a name that is not a string', '{"name":{"name":"srv"}}', undefined],
    ['a name with bad characters', '{"name":"srv <script>"}', undefined],
    ['a name only in __proto__', '{"__proto__":{"name":"srv"}}', undefined],
    ['longer than 512 characters', `{"name":"srv","pad":"${'x'.repeat(512)}"}`, undefined],
  ])('reads an mta_module that is %s', (_name, json, expected) => {
    expect(parse({ annotations: { mta_module: json } }).annotations.mta_module).toBe(expected);
  });

  it('never fails the app it belongs to', () => {
    const resource = (metadata: unknown) => ({
      guid: 'a0000000-0000-4000-8000-000000000001',
      name: 'incidents-srv',
      state: 'STARTED',
      lifecycle: { type: 'buildpack', data: { buildpacks: ['nodejs_buildpack'] } },
      ...(metadata === undefined ? {} : { metadata }),
    });
    const hostile = [
      undefined,
      null,
      'text',
      { labels: null, annotations: 3 },
      { labels: { mta_id: ['x'] }, annotations: { mta_id: 'a'.repeat(6000), mta_module: '{' } },
      { annotations: { contact: 'owner@example.com' } },
      { labels: { mta_namespace: null }, annotations: { mta_namespace: 'n'.repeat(6000) } },
      { labels: { mta_namespace: ['owner@example.com'] }, annotations: { mta_namespace: 7 } },
    ];
    for (const metadata of hostile) {
      const parsed = CfAppSchema.safeParse(resource(metadata));
      expect(parsed.success, JSON.stringify(metadata)).toBe(true);
      expect(JSON.stringify(parsed.data)).not.toContain('example.com');
    }
    const valid = CfAppSchema.parse(resource(deployed('acme', { module: 'srv' })));
    expect(mtaIdentity(valid.metadata)).toEqual({
      id: 'acme',
      version: '1.0.0',
      module: 'srv',
      namespace: null,
    });
  });
});

describe('belonging to an MTA project', () => {
  it('hashes a value as the deploy service does: lower-case hex MD5 of its UTF-8 bytes', () => {
    expect(hashedLabel('')).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(hashedLabel('acme')).toBe(md5('acme'));
    expect(hashedLabel('acme')).toMatch(/^[0-9a-f]{32}$/);
  });

  it('needs the label to be the MD5 of the annotation', () => {
    expect(mtaIdentity(parse(deployed('acme', { version: '1.2.0', module: 'srv' })))).toEqual({
      id: 'acme',
      version: '1.2.0',
      module: 'srv',
      namespace: null,
    });
    // The label of another id: the two values disagree.
    expect(
      mtaIdentity(parse({ labels: { mta_id: md5('other') }, annotations: { mta_id: 'acme' } })),
    ).toBeNull();
    // An upper-case digest is not what the deploy service writes.
    expect(
      mtaIdentity(
        parse({ labels: { mta_id: md5('acme').toUpperCase() }, annotations: { mta_id: 'acme' } }),
      ),
    ).toBeNull();
    expect(mtaIdentity(parse({ annotations: { mta_id: 'acme' } }))).toBeNull();
    expect(mtaIdentity(parse({ labels: { mta_id: md5('acme') } }))).toBeNull();
    expect(mtaIdentity(parse(undefined))).toBeNull();
  });

  it('keeps the id without a version or a module', () => {
    const metadata = parse({ labels: { mta_id: md5('acme') }, annotations: { mta_id: 'acme' } });
    expect(mtaIdentity(metadata)).toEqual({
      id: 'acme',
      version: null,
      module: null,
      namespace: null,
    });
  });

  it('needs a consistent namespace: none, or a label that is the MD5 of the annotation', () => {
    const base = deployed('acme');
    expect(mtaIdentity(parse(deployed('acme', { namespace: 'blue' })))?.namespace).toBe('blue');
    // A label without an annotation.
    expect(
      mtaIdentity(parse({ ...base, labels: { ...base.labels, mta_namespace: md5('blue') } })),
    ).toBeNull();
    // An annotation without a label.
    expect(
      mtaIdentity(parse({ ...base, annotations: { ...base.annotations, mta_namespace: 'blue' } })),
    ).toBeNull();
    // A label of another namespace.
    expect(
      mtaIdentity(
        parse({
          labels: { ...base.labels, mta_namespace: md5('green') },
          annotations: { ...base.annotations, mta_namespace: 'blue' },
        }),
      ),
    ).toBeNull();
    // A namespace that is not a plain name is left out, so its label stands alone.
    expect(
      mtaIdentity(
        parse({
          labels: { ...base.labels, mta_namespace: md5('blue green') },
          annotations: { ...base.annotations, mta_namespace: 'blue green' },
        }),
      ),
    ).toBeNull();
  });

  it.each([
    ['an annotation that is not a plain name', {}, { mta_namespace: 'bad namespace!' }],
    ['an annotation that is too long', {}, { mta_namespace: 'n'.repeat(37) }],
    ['an empty annotation', {}, { mta_namespace: '' }],
    ['a null annotation', {}, { mta_namespace: null }],
    ['an annotation of the wrong type', {}, { mta_namespace: 7 }],
    ['a label that is not a digest', { mta_namespace: 'ZZ' }, {}],
    ['a null label', { mta_namespace: null }, {}],
    ['a label of the wrong type', { mta_namespace: ['x'] }, {}],
    ['an unusable label and annotation', { mta_namespace: 'ZZ' }, { mta_namespace: 'bad!' }],
    [
      'a digest label next to an unusable annotation',
      { mta_namespace: md5('bad!') },
      { mta_namespace: 'bad!' },
    ],
    [
      'a valid annotation next to an unusable label',
      { mta_namespace: 'ZZ' },
      { mta_namespace: 'blue' },
    ],
  ])(
    'takes an app with %s for its namespace as an app on its own, not as part of the deployment without one',
    (_name, labels, annotations) => {
      const base = deployed('acme');
      const metadata = parse({
        labels: { ...base.labels, ...labels },
        annotations: { ...base.annotations, ...annotations },
      });
      // The id pair is the deploy service's; only the namespace is off.
      expect(mtaIdentity(parse(base))?.id).toBe('acme');
      expect(mtaIdentity(metadata)).toBeNull();
      const { projects, singles } = groupByMta([
        app('acme-srv', base),
        { name: 'acme-odd', metadata },
      ]);
      expect(projects.map((project) => names(project.members.map((m) => m.app)))).toEqual([
        ['acme-srv'],
      ]);
      expect(names(singles)).toEqual(['acme-odd']);
      // Nothing of the unusable value is kept, only that the key was there.
      expect(JSON.stringify(metadata)).not.toMatch(/bad|ZZ|nnnn/);
    },
  );
});

describe('grouping the apps of a space', () => {
  const apps = [
    app('billing-srv', deployed('billing', { module: 'srv' })),
    app('incidents-db', deployed('acme', { module: 'db', namespace: 'blue' })),
    app('incidents-db-live', deployed('acme', { module: 'db' })),
    app('legacy-ui'),
    app('incidents-srv', deployed('acme', { module: 'srv', namespace: 'blue' })),
    app('spoofed', { labels: { mta_id: md5('other') }, annotations: { mta_id: 'acme' } }),
    app('incidents-srv-live', deployed('acme', { module: 'srv' })),
    app('Zeta-srv', deployed('Zeta')),
  ];

  it('makes one project per id and namespace, sorted by id then namespace', () => {
    const { projects } = groupByMta(apps);
    expect(projects.map((p) => [p.id, p.namespace])).toEqual([
      ['Zeta', null],
      ['acme', null],
      ['acme', 'blue'],
      ['billing', null],
    ]);
  });

  it('keeps the apps of a project and the apps on their own in the order given', () => {
    const { projects, singles } = groupByMta(apps);
    const byTitle = Object.fromEntries(
      projects.map((p) => [
        projectTitle(p),
        p.members.map((m) => `${m.app.name}:${m.mta.module ?? '-'}`),
      ]),
    );
    expect(byTitle).toEqual({
      'Zeta 1.0.0': ['Zeta-srv:-'],
      'acme 1.0.0': ['incidents-db-live:db', 'incidents-srv-live:srv'],
      'acme 1.0.0 (namespace blue)': ['incidents-db:db', 'incidents-srv:srv'],
      'billing 1.0.0': ['billing-srv:srv'],
    });
    // An app whose label is not the MD5 of its annotation is an app on its own.
    expect(names(singles)).toEqual(['legacy-ui', 'spoofed']);
  });

  it('finds no project among apps without MTA metadata', () => {
    const plain = [app('a'), app('b', { labels: { team: 'x' } })];
    expect(groupByMta(plain)).toEqual({ projects: [], singles: plain });
    expect(groupByMta([])).toEqual({ projects: [], singles: [] });
  });
});

describe('the picker entry of a project', () => {
  const project = (members: MtaApp[]) => {
    const [first] = groupByMta(members).projects;
    if (first === undefined) throw new Error('no project in the test data');
    return first;
  };
  const all = (): boolean => true;

  it('names the id, the version, the app count and each app with its module', () => {
    const acme = project([
      app('incidents-db', deployed('acme', { version: '1.2.0', module: 'db' })),
      app('incidents-srv', deployed('acme', { version: '1.2.0', module: 'srv' })),
      app('incidents-worker', deployed('acme', { version: '1.2.0' })),
    ]);
    expect(projectLabel(acme, all)).toBe(
      'acme 1.2.0 · project, 3 app(s): incidents-db (db), incidents-srv (srv), incidents-worker',
    );
  });

  it('says how many of the apps can be read, and lists only those', () => {
    const acme = project([
      app('incidents-db', deployed('acme', { module: 'db' })),
      app('incidents-srv', deployed('acme', { module: 'srv' })),
      app('incidents-ui', deployed('acme', { module: 'ui' })),
    ]);
    expect(projectLabel(acme, (a) => a.name !== 'incidents-db')).toBe(
      'acme 1.0.0 · project, 2 of 3 apps: incidents-srv (srv), incidents-ui (ui)',
    );
  });

  it('shows the version only when every app carries the same one', () => {
    const mixed = project([
      app('a', deployed('acme', { version: '1.0.0' })),
      app('b', deployed('acme', { version: '1.1.0' })),
    ]);
    expect(projectVersion(mixed)).toBeNull();
    expect(projectLabel(mixed, all)).toBe('acme · project, 2 app(s): a, b');

    const partial = project([
      app('a', deployed('acme', { version: '1.0.0' })),
      app('b', { labels: { mta_id: md5('acme') }, annotations: { mta_id: 'acme' } }),
    ]);
    expect(projectVersion(partial)).toBeNull();

    const none = project([
      app('a', { labels: { mta_id: md5('acme') }, annotations: { mta_id: 'acme' } }),
    ]);
    expect(projectVersion(none)).toBeNull();
    expect(projectTitle(none)).toBe('acme');
  });

  it('names the namespace of a deployment that has one', () => {
    const blue = project([app('a', deployed('acme', { version: '2.0.0', namespace: 'blue' }))]);
    expect(projectLabel(blue, all)).toBe('acme 2.0.0 (namespace blue) · project, 1 app(s): a');
    expect(deploymentName('blue')).toBe('namespace blue');
    expect(deploymentName(null)).toBe('without a namespace');
  });

  it('lists ten apps, then says how many more there are', () => {
    const many = project(
      Array.from({ length: 13 }, (_, i) =>
        app(`app-${String(i + 1).padStart(2, '0')}`, deployed('acme')),
      ),
    );
    const label = projectLabel(many, all);
    expect(label).toBe(
      'acme 1.0.0 · project, 13 app(s): app-01, app-02, app-03, app-04, app-05, app-06, app-07, app-08, app-09, app-10 and 3 more',
    );
    const ten = project(Array.from({ length: 10 }, (_, i) => app(`app-${i}`, deployed('acme'))));
    expect(projectLabel(ten, all)).not.toContain('more');
  });
});

describe('the app limit of a project', () => {
  const sized = (count: number) => {
    const members = Array.from({ length: count }, (_, i) => app(`app-${i}`, deployed('big')));
    const [project] = groupByMta(members).projects;
    if (project === undefined) throw new Error('no project in the test data');
    return project;
  };

  it('is 50 apps: a project with more is not read as a whole', () => {
    expect(MAX_PROJECT_APPS).toBe(50);
    expect(overAppLimit(sized(50))).toBe(false);
    expect(overAppLimit(sized(51))).toBe(true);
  });

  it('says how many apps there are and how to read one of them', () => {
    expect(overAppLimitWhy(51)).toBe(
      'it has 51 apps, more than the 50 one run reads; read one app with --app <name>',
    );
  });
});

describe('project ids of deployed apps', () => {
  const sha8 = (name: string): string =>
    createHash('sha256').update(name, 'utf8').digest('hex').slice(0, 8);
  const ids = (appNames: string[]): string[] =>
    withProjectIds(appNames, (name) => name).map((entry) => entry.id);

  it('uses the app name when it is a valid id', () => {
    expect(projectIdOf('incidents-srv')).toBe('incidents-srv');
    expect(projectIdOf('acme.incidents_srv-2')).toBe('acme.incidents_srv-2');
    expect(projectIdOf('a'.repeat(64))).toBe('a'.repeat(64));
  });

  it('derives an id from a name that is not one: what is left of it, and a hash of all of it', () => {
    expect(projectIdOf('my app (blue)')).toBe(`my-app-blue-${sha8('my app (blue)')}`);
    expect(projectIdOf('my app (blue)')).toBe('my-app-blue-9ea3f794');
    expect(projectIdOf(' -- srv/api -- ')).toBe(`srv-api-${sha8(' -- srv/api -- ')}`);
  });

  it('cuts a long name to 48 characters before the hash', () => {
    const long = 'x'.repeat(81);
    const id = projectIdOf(long);
    expect(id).toBe(`${'x'.repeat(48)}-${sha8(long)}`);
    expect(id).toHaveLength(57);
    // 65 characters of the id alphabet are one too many for an id, too.
    expect(projectIdOf('y'.repeat(65))).toBe(`${'y'.repeat(48)}-${sha8('y'.repeat(65))}`);
  });

  it('calls a name without any usable character "app"', () => {
    expect(projectIdOf('—')).toBe('app-bda05058');
    expect(projectIdOf('日本語アプリ')).toBe(`app-${sha8('日本語アプリ')}`);
    expect(projectIdOf('日本語アプリ')).not.toBe(projectIdOf('—'));
  });

  it('always gives a valid id', () => {
    const odd = ['', ' ', '..', '-', 'a b', 'ä'.repeat(300), 'x'.repeat(255), '\u0000', '😀 app'];
    for (const name of odd) expect(projectIdOf(name), name).toMatch(PROJECT_ID_PATTERN);
  });

  it('keeps two names apart that leave the same text', () => {
    const [first, second] = ids(['my app', 'my/app']);
    expect(first).toBe(`my-app-${sha8('my app')}`);
    expect(second).toBe(`my-app-${sha8('my/app')}`);
    expect(first).not.toBe(second);
  });

  it('never gives a derived id that is the name of another app', () => {
    const plain = 'my-app-blue-9ea3f794';
    expect(ids(['my app (blue)', plain])).toEqual([`${plain}-2`, plain]);
    expect(ids([plain, 'my app (blue)'])).toEqual([plain, `${plain}-2`]);
  });

  it('numbers an id that is taken, and stays within 64 characters', () => {
    expect(ids(['a', 'a', 'a'])).toEqual(['a', 'a-2', 'a-3']);
    // The number never lands on the name of an app that comes later.
    expect(ids(['a', 'a', 'a-2'])).toEqual(['a', 'a-3', 'a-2']);
    const long = 'z'.repeat(64);
    const numbered = ids([long, long]);
    expect(numbered).toEqual([long, `${'z'.repeat(62)}-2`]);
    for (const id of numbered) expect(id).toMatch(PROJECT_ID_PATTERN);
  });

  it('keeps each item with its id, in the order given', () => {
    const items = [{ app: 'b c' }, { app: 'a' }];
    expect(withProjectIds(items, (item) => item.app)).toEqual([
      { item: items[0], id: `b-c-${sha8('b c')}` },
      { item: items[1], id: 'a' },
    ]);
    expect(withProjectIds([], (name: string) => name)).toEqual([]);
  });
});
