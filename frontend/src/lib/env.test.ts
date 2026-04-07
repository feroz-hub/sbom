import { describe, expect, it, afterEach, beforeEach } from 'vitest';
import { resolveBaseUrl } from '@/lib/env';

describe('resolveBaseUrl', () => {
  const savedEnv = process.env.NEXT_PUBLIC_API_URL;

  beforeEach(() => {
    delete process.env.NEXT_PUBLIC_API_URL;
  });

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.NEXT_PUBLIC_API_URL;
    } else {
      process.env.NEXT_PUBLIC_API_URL = savedEnv;
    }
  });

  it('returns the value when explicitly passed in', () => {
    expect(resolveBaseUrl('http://api.example.com')).toBe('http://api.example.com');
  });

  it('reads from process.env.NEXT_PUBLIC_API_URL when no argument is given', () => {
    process.env.NEXT_PUBLIC_API_URL = 'http://env.example.com';
    expect(resolveBaseUrl()).toBe('http://env.example.com');
  });

  it('strips a single trailing slash', () => {
    expect(resolveBaseUrl('http://api.example.com/')).toBe('http://api.example.com');
  });

  it('does not strip internal slashes', () => {
    expect(resolveBaseUrl('http://api.example.com/v1/')).toBe('http://api.example.com/v1');
  });

  it('throws when the env var is undefined', () => {
    expect(() => resolveBaseUrl()).toThrowError(/NEXT_PUBLIC_API_URL is not configured/);
  });

  it('throws when passed an empty string', () => {
    expect(() => resolveBaseUrl('')).toThrowError(/NEXT_PUBLIC_API_URL is not configured/);
  });

  it('throws when passed whitespace-only', () => {
    expect(() => resolveBaseUrl('   ')).toThrowError(/NEXT_PUBLIC_API_URL is not configured/);
  });

  it('throws when passed undefined explicitly and env is also unset', () => {
    expect(() => resolveBaseUrl(undefined)).toThrowError(/NEXT_PUBLIC_API_URL is not configured/);
  });

  it('produces a clean concatenation with request paths', () => {
    const base = resolveBaseUrl('http://api.example.com/');
    expect(`${base}/api/sboms`).toBe('http://api.example.com/api/sboms');
  });
});
