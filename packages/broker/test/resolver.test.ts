import { describe, it, expect } from 'vitest';
import { createResolver } from '../src/index.js';

/**
 * Broker DNS resolution (§7.1 step 11). Proves the adapter resolves A+AAAA, merges them, tolerates a per-family
 * NODATA (only one family answering is normal), and returns an empty list when nothing resolves — so `resolveAndPin`
 * can fail closed. The real `node:dns` binding is the injectable boundary; here it is faked for determinism.
 */

const reject = (): Promise<readonly string[]> => Promise.reject(new Error('ENODATA'));
const resolveWith = (addrs: readonly string[]) => (): Promise<readonly string[]> =>
  Promise.resolve(addrs);

describe('createResolver', () => {
  it('merges A (v4) and AAAA (v6) answers', async () => {
    const r = createResolver({
      resolve4: resolveWith(['1.2.3.4']),
      resolve6: resolveWith(['2606::1']),
    });
    expect(await r('host')).toEqual(['1.2.3.4', '2606::1']);
  });

  it('returns only the family that resolved when the other NODATAs (never throws)', async () => {
    const v4only = createResolver({ resolve4: resolveWith(['1.2.3.4']), resolve6: reject });
    const v6only = createResolver({ resolve4: reject, resolve6: resolveWith(['2606::1']) });
    expect(await v4only('host')).toEqual(['1.2.3.4']);
    expect(await v6only('host')).toEqual(['2606::1']);
  });

  it('returns an empty list when BOTH families fail (⇒ resolveAndPin denies no_resolution)', async () => {
    const none = createResolver({ resolve4: reject, resolve6: reject });
    expect(await none('host')).toEqual([]);
  });

  it('dedupes repeated / cross-family duplicate addresses', async () => {
    const r = createResolver({
      resolve4: resolveWith(['1.2.3.4', '1.2.3.4']),
      resolve6: resolveWith(['1.2.3.4']),
    });
    expect(await r('host')).toEqual(['1.2.3.4']);
  });
});
