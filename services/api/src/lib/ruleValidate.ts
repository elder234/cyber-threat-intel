/**
 * Module 2 — detection-rule validation (YARA / Sigma).
 *
 * These are *structural* validators, not full compilers: they confirm a rule is
 * well-formed enough to store and hand to an external engine (yara / sigmac /
 * pySigma) without surprises. We deliberately avoid new dependencies — Sigma is
 * validated with a minimal YAML-subset reader rather than a full YAML parser.
 *
 * Pure functions — unit-tested; no DB or network.
 */

export interface RuleValidation {
  valid: boolean;
  /** Extracted rule name/title when we can find one (helps auto-fill). */
  name?: string;
  /** Author-assigned external id (Sigma `id:`), if present. */
  ruleIdExt?: string;
  /** ATT&CK technique ids parsed from tags (e.g. `attack.t1566` → `T1566`). */
  techniqueIds: string[];
  error?: string;
}

/** Dispatch on declared format. */
export function validateRule(format: 'yara' | 'sigma', content: string): RuleValidation {
  return format === 'yara' ? validateYara(content) : validateSigma(content);
}

// ── YARA ─────────────────────────────────────────────────────────────────────

/**
 * Validate a YARA rule structurally: at least one `rule <ident> { ... }` block
 * with a `condition:` section and balanced braces. Multiple rules are allowed;
 * the first rule's name is returned.
 */
export function validateYara(content: string): RuleValidation {
  const text = content.trim();
  if (!text) return { valid: false, techniqueIds: [], error: 'empty rule' };

  // Strip /* */ and // comments so braces/keywords inside them don't confuse us.
  const stripped = text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\/\/[^\n]*/g, ' ');

  const ruleRe = /\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^\{]*)?\{/g;
  const names: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = ruleRe.exec(stripped)) !== null) names.push(m[1]);
  if (names.length === 0) {
    return { valid: false, techniqueIds: [], error: 'no `rule <name> { … }` block found' };
  }

  // Balanced braces across the whole file.
  let depth = 0;
  for (const ch of stripped) {
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth < 0) break; }
  }
  if (depth !== 0) {
    return { valid: false, techniqueIds: [], error: 'unbalanced braces' };
  }

  if (!/\bcondition\s*:/.test(stripped)) {
    return { valid: false, techniqueIds: [], error: 'missing `condition:` section' };
  }

  return { valid: true, name: names[0], techniqueIds: extractAttackFromText(stripped) };
}

// ── Sigma ──────────────────────────────────────────────────────────────────────

/**
 * Validate a Sigma rule (YAML). Requires `title`, `detection`, and a
 * `condition` inside detection. Parsed with a minimal top-level YAML reader —
 * enough to confirm required keys and pull `title`/`id`/`tags`.
 */
export function validateSigma(content: string): RuleValidation {
  const text = content.replace(/\r\n/g, '\n').trim();
  if (!text) return { valid: false, techniqueIds: [], error: 'empty rule' };

  // Reject obvious JSON — Sigma is YAML.
  if (text.startsWith('{')) {
    return { valid: false, techniqueIds: [], error: 'expected YAML, got JSON' };
  }

  const topKeys = topLevelYamlKeys(text);
  const has = (k: string) => topKeys.has(k);

  if (!has('title')) return { valid: false, techniqueIds: [], error: 'missing `title`' };
  if (!has('detection')) return { valid: false, techniqueIds: [], error: 'missing `detection`' };

  // `condition:` must appear indented under detection (any nesting).
  if (!/\n\s+condition\s*:/.test('\n' + text)) {
    return { valid: false, techniqueIds: [], error: 'missing `condition` in detection' };
  }

  const title = scalarValue(text, 'title');
  const id = scalarValue(text, 'id');
  return {
    valid: true,
    name: title,
    ruleIdExt: id,
    techniqueIds: extractAttackFromText(text),
  };
}

// ── helpers ────────────────────────────────────────────────────────────────────

/** Keys at indentation 0 (`key:` at start of a line). */
function topLevelYamlKeys(text: string): Set<string> {
  const keys = new Set<string>();
  for (const line of text.split('\n')) {
    const mm = /^([A-Za-z0-9_-]+)\s*:/.exec(line);
    if (mm) keys.add(mm[1]);
  }
  return keys;
}

/** Value of a top-level scalar key, quotes stripped. */
function scalarValue(text: string, key: string): string | undefined {
  const re = new RegExp(`^${key}\\s*:\\s*(.+)$`, 'm');
  const mm = re.exec(text);
  if (!mm) return undefined;
  return mm[1].trim().replace(/^['"]|['"]$/g, '') || undefined;
}

/**
 * Pull ATT&CK technique ids from Sigma-style `attack.t1566.001` tags or bare
 * `T1566` mentions. Normalizes to upper-case `T####[.###]`, de-duplicated.
 */
export function extractAttackFromText(text: string): string[] {
  const ids = new Set<string>();
  const re = /\b[tT]\d{4}(?:\.\d{3})?\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) ids.add(m[0].toUpperCase());
  return [...ids].sort();
}
