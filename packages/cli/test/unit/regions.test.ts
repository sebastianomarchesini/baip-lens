import { describe, expect, it } from 'vitest';
import { parseApiUrl } from '../../src/config.js';
import {
  REGIONS,
  REGIONS_VERIFIED_ON,
  REGION_NOT_LISTED,
  regionForApi,
  regionIdOf,
  regionListLines,
  toApiEndpoint,
} from '../../src/guided/regions.js';

describe('region list', () => {
  it('has unique ids and https API endpoints', () => {
    expect(new Set(REGIONS.map((r) => r.id)).size).toBe(REGIONS.length);
    for (const r of REGIONS) expect(r.api).toMatch(/^https:\/\/api\.cf\.[a-z]{2}\d{2}(-\d{3})?\./);
  });

  it('includes the extension landscapes', () => {
    const ids = REGIONS.map((r) => r.id);
    for (const id of [
      'eu10-002',
      'eu10-003',
      'eu10-004',
      'eu10-005',
      'us10-001',
      'us10-002',
      'eu20-001',
      'eu20-002',
    ]) {
      expect(ids).toContain(id);
    }
  });
});

describe('toApiEndpoint', () => {
  it.each([
    ['us10-001.hana.ondemand.com', 'https://api.cf.us10-001.hana.ondemand.com'],
    ['https://us10-001.hana.ondemand.com/', 'https://api.cf.us10-001.hana.ondemand.com'],
    ['cf.eu10-004.hana.ondemand.com', 'https://api.cf.eu10-004.hana.ondemand.com'],
    ['eu10-004', 'https://api.cf.eu10-004.hana.ondemand.com'],
    [' CF-EU10-004 ', 'https://api.cf.eu10-004.hana.ondemand.com'],
    ['us21-001', 'https://api.cf.us21-001.hana.ondemand.com'],
    ['cn40', 'https://api.cf.cn40.platform.sapcloud.cn'],
    ['cn20.platform.sapcloud.cn', 'https://api.cf.cn20.platform.sapcloud.cn'],
  ])('%s → %s', (input, expected) => {
    expect(toApiEndpoint(input)).toBe(expected);
  });

  it.each([
    'https://api.cf.us10-001.hana.ondemand.com',
    'api.cf.eu10.hana.ondemand.com',
    'https://api.cf.example.org',
    'myapp.cfapps.eu10.hana.ondemand.com',
    'http://us10-001.hana.ondemand.com',
  ])('leaves %s unchanged', (input) => {
    expect(toApiEndpoint(input)).toBe(input);
  });

  it('is applied by parseApiUrl', () => {
    expect(parseApiUrl('us10-001.hana.ondemand.com').href).toBe(
      'https://api.cf.us10-001.hana.ondemand.com/',
    );
    expect(() => parseApiUrl('http://us10-001.hana.ondemand.com')).toThrow(/https/);
  });
});

describe('regionIdOf', () => {
  it.each([
    ['eu10', 'eu10'],
    [' US01 ', 'us01'],
    ['us10-001', 'us10-001'],
    ['us10.001', 'us10-001'],
    ['cf-eu10-004', 'eu10-004'],
  ])('%s → %s', (input, expected) => {
    expect(regionIdOf(input)).toBe(expected);
  });

  it.each(['us10-001.hana.ondemand.com', 'https://api.cf.eu10.hana.ondemand.com', 'list', ''])(
    'is undefined for %s',
    (input) => {
      expect(regionIdOf(input)).toBeUndefined();
    },
  );

  it('accepts a dot between region and landscape number wherever an endpoint is asked', () => {
    expect(toApiEndpoint('us10.001')).toBe('https://api.cf.us10-001.hana.ondemand.com');
    expect(parseApiUrl('EU10.004').host).toBe('api.cf.eu10-004.hana.ondemand.com');
  });
});

describe('regionForApi', () => {
  it('finds the listed region of an API endpoint, including the China domain', () => {
    expect(regionForApi(new URL('https://api.cf.eu10.hana.ondemand.com'))?.id).toBe('eu10');
    expect(regionForApi(new URL('https://api.cf.cn40.platform.sapcloud.cn/'))?.id).toBe('cn40');
    expect(regionForApi(new URL('https://api.cf.example.org'))).toBeUndefined();
  });
});

describe('regionListLines', () => {
  it('lists every region once, id first, and says what to do when one is missing', () => {
    const lines = regionListLines();
    for (const r of REGIONS) {
      expect(lines.filter((l) => l.trim().split(/\s{2,}/)[0] === r.id)).toEqual([
        expect.stringContaining(r.label),
      ]);
    }
    expect(lines[0]).toContain(REGIONS_VERIFIED_ON);
    expect(lines).toContain(REGION_NOT_LISTED);
  });
});
