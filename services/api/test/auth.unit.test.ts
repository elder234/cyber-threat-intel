import { describe, it, expect } from 'vitest';
import { sha256, newRefreshToken } from '../src/lib/auth.js';

/**
 * Pure-function unit tests that need no database. The DB-backed flows
 * (authenticate, refresh rotation) are covered by integration tests that
 * require a live Postgres — see auth.integration.test.ts (marked runtime).
 */
describe('auth helpers', () => {
  it('sha256 is stable and hex-encoded', () => {
    const h = sha256('hello');
    expect(h).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('newRefreshToken returns a token whose sha256 matches the stored hash', () => {
    const { token, hash } = newRefreshToken();
    expect(token.length).toBeGreaterThan(40);
    expect(hash).toBe(sha256(token));
  });

  it('refresh tokens are unique per call', () => {
    const a = newRefreshToken();
    const b = newRefreshToken();
    expect(a.token).not.toBe(b.token);
    expect(a.hash).not.toBe(b.hash);
  });
});
