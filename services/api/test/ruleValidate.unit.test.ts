import { describe, it, expect } from 'vitest';
import { validateYara, validateSigma, validateRule, extractAttackFromText } from '../src/lib/ruleValidate.js';

/**
 * Pure structural-validation tests (no DB). The route that persists rules is
 * covered by the integration suite (marked runtime — needs live Postgres).
 */

describe('YARA validation', () => {
  const good = `
    /* detects a silly string */
    rule Silly_Detector : malware {
      meta:
        author = "soc"
        attack = "T1059.001"
      strings:
        $a = "evil"
      condition:
        $a
    }`;

  it('accepts a well-formed rule and extracts the name', () => {
    const v = validateYara(good);
    expect(v.valid).toBe(true);
    expect(v.name).toBe('Silly_Detector');
    expect(v.techniqueIds).toContain('T1059.001');
  });

  it('rejects a rule with no rule block', () => {
    const v = validateYara('strings: $a = "x" condition: $a');
    expect(v.valid).toBe(false);
    expect(v.error).toMatch(/rule/);
  });

  it('rejects unbalanced braces', () => {
    const v = validateYara('rule R { condition: true ');
    expect(v.valid).toBe(false);
    expect(v.error).toMatch(/brace/);
  });

  it('rejects a rule missing its condition', () => {
    const v = validateYara('rule R { strings: $a = "x" }');
    expect(v.valid).toBe(false);
    expect(v.error).toMatch(/condition/);
  });

  it('ignores braces inside comments', () => {
    const v = validateYara('rule R { /* } */ condition: true }');
    expect(v.valid).toBe(true);
  });
});

describe('Sigma validation', () => {
  const good = `
title: Suspicious PowerShell Download
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: experimental
tags:
    - attack.execution
    - attack.t1059.001
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
level: high`;

  it('accepts a well-formed sigma rule', () => {
    const v = validateSigma(good);
    expect(v.valid).toBe(true);
    expect(v.name).toBe('Suspicious PowerShell Download');
    expect(v.ruleIdExt).toBe('3b6ab547-8ec2-4991-b9d2-2b06702a48d7');
    expect(v.techniqueIds).toContain('T1059.001');
  });

  it('rejects when title is missing', () => {
    const v = validateSigma('detection:\n    condition: selection');
    expect(v.valid).toBe(false);
    expect(v.error).toMatch(/title/);
  });

  it('rejects when detection is missing', () => {
    const v = validateSigma('title: X');
    expect(v.valid).toBe(false);
    expect(v.error).toMatch(/detection/);
  });

  it('rejects when condition is missing inside detection', () => {
    const v = validateSigma('title: X\ndetection:\n    selection:\n        a: b');
    expect(v.valid).toBe(false);
    expect(v.error).toMatch(/condition/);
  });

  it('rejects JSON masquerading as sigma', () => {
    const v = validateSigma('{"title":"x"}');
    expect(v.valid).toBe(false);
  });
});

describe('validateRule dispatch + attack extraction', () => {
  it('dispatches to the right validator', () => {
    expect(validateRule('yara', 'rule R { condition: true }').valid).toBe(true);
    expect(validateRule('sigma', 'title: X\ndetection:\n    condition: sel').valid).toBe(true);
  });

  it('normalizes and de-dupes technique ids', () => {
    const ids = extractAttackFromText('attack.t1566 and T1566 and t1566.001');
    expect(ids).toEqual(['T1566', 'T1566.001']);
  });
});
