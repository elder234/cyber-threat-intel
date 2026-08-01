// Shared domain types mirrored from the API (services/api). Kept intentionally
// narrow — only the fields the SOC console renders. ⚠️ RUNTIME VERIFICATION
// REQUIRED: shapes are transcribed from the Fastify route handlers, not from a
// live response, until the API can be run against the DB.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high' | 'confirmed';
export type Tlp = 'clear' | 'green' | 'amber' | 'amber_strict' | 'red';

export interface AuthUser {
  sub: string;
  email: string;
  roles: string[];
  perms?: string[];
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  user: { id: string; email: string; roles: string[] };
}

export interface Pagination {
  total?: number;
  limit: number;
  offset: number;
}

export interface Paged<T> {
  data: T[];
  pagination: Pagination;
}

export type IocType =
  | 'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'sha512'
  | 'email' | 'cidr' | 'asn' | 'file_path' | 'registry_key' | 'mutex'
  | 'user_agent' | 'ja3';

export interface Ioc {
  id: string;
  type: IocType;
  value: string;
  severity: Severity;
  confidence: Confidence;
  tlp: Tlp;
  score: number | null;
  is_active: boolean;
  tags: string[];
  source: string;
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
}

export interface Cve {
  cve_id: string;
  description: string;
  cvss_v31_score: number | null;
  cvss_v31_severity: Severity | null;
  epss_score: number | null;
  epss_percentile: number | null;
  kev: boolean;
  kev_ransomware: boolean;
  published_at: string | null;
}

export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'suppressed';

export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  source: string | null;
  summary: string | null;
  created_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
}

export interface Feed {
  id: string;
  name: string;
  provider: string;
  format: string;
  enabled: boolean;
  interval_secs: number;
  last_run_at: string | null;
  last_status: string | null;
  last_item_count: number | null;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface Scan {
  id: string;
  target: string;
  scan_type: string;
  status: ScanStatus;
  progress: number | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface DashboardStats {
  iocs_total: number;
  iocs_active: number;
  cves_kev: number;
  alerts_open: number;
  scans_running: number;
  feeds_healthy: number;
  feeds_total: number;
  risk_score: number;
  by_severity: Record<Severity, number>;
  ingest_24h: number;
}

export interface TimelineEvent {
  ts: string;
  kind: string;
  severity: Severity;
  title: string;
}

export interface AttackStat {
  tactic: string;
  count: number;
}

export interface TopSource {
  source: string;
  count: number;
  high_sev: number;
}

export interface SearchResult {
  entity_type: string;
  entity_id: string;
  label: string;
  sub_label?: string | null;
  severity?: Severity | null;
  rank?: number;
}

export type RuleFormat = 'yara' | 'sigma';
export type RuleStatus = 'stable' | 'test' | 'experimental' | 'deprecated';

export interface DetectionRule {
  id: string;
  format: RuleFormat;
  name: string;
  rule_id_ext: string | null;
  content?: string;
  description: string;
  author: string | null;
  severity: Severity;
  status: RuleStatus;
  tags: string[];
  technique_ids: string[];
  is_enabled: boolean;
  is_valid: boolean | null;
  validation_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface RuleValidation {
  valid: boolean;
  name?: string;
  ruleIdExt?: string;
  techniqueIds: string[];
  error?: string;
}

// ── Module 11 — alerting configuration ──────────────────────────────────────
export type ChannelType = 'email' | 'slack' | 'discord' | 'telegram' | 'webhook';

export interface NotificationChannel {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  min_severity: Severity;
  config: Record<string, unknown>;   // redacted server-side
  last_ok_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export type AlertRuleEventType = 'ioc.new' | 'cve.kev' | 'cve.new' | 'scan.finding' | 'feed.error';

export interface AlertRuleConditions {
  min_severity?: Severity;
  tags_any?: string[];
  tags_all?: string[];
  sources?: string[];
  value_regex?: string;
}

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  event_type: AlertRuleEventType;
  conditions: AlertRuleConditions;
  severity: Severity;
  channels: string[];
  throttle_secs: number;
  created_at: string;
  updated_at: string;
}

export interface ChannelTestResult {
  channel: string;
  ok: boolean;
  error?: string;
}

// ── Module 6: container security audits ──────────────────────────────────────
export type ContainerAuditKind = 'dockerfile' | 'image_config' | 'trivy';
export type ContainerFindingCategory =
  'dockerfile' | 'image_config' | 'vulnerability' | 'secret' | 'compose';

export interface ContainerRiskSummary {
  score: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ContainerAudit {
  id: string;
  name: string;
  kind: ContainerAuditKind;
  status: 'queued' | 'running' | 'completed' | 'failed';
  score: number | null;
  summary: Partial<ContainerRiskSummary>;
  error: string | null;
  created_at: string;
  updated_at: string;
  finished_at: string | null;
}

export interface ContainerFinding {
  id: number;
  rule_id: string;
  category: ContainerFindingCategory;
  severity: Severity;
  title: string;
  remediation: string;
  location: string | null;
  created_at: string;
}

export interface ContainerAuditDetail extends ContainerAudit {
  input: string;
  findings: ContainerFinding[];
}

// ── Module 9: malware static analysis ────────────────────────────────────────
export interface MalwareSample {
  id: string;
  name: string;
  sha256: string;
  sha1: string | null;
  md5: string | null;
  size_bytes: number;
  file_type: string | null;
  file_type_label: string | null;
  entropy: number | null;
  status: string;
  score: number | null;
  summary: Record<string, unknown>;
  error: string | null;
  created_at: string;
}

export interface MalwareFinding {
  id: number;
  rule_id: string;
  severity: Severity;
  title: string;
  detail: string;
  created_at: string;
}

export interface MalwareSampleDetail extends MalwareSample {
  indicators: unknown[];
  suspicious: unknown[];
  findings: MalwareFinding[];
}

// WebSocket envelope pushed over /ws (Redis "events" channel fan-out).
export type LiveEvent =
  | { type: 'hello'; ts: number }
  | { type: 'error'; message: string }
  | { type: 'ioc.new'; id: string; severity: Severity; value: string }
  | { type: 'alert.new'; id: string; severity: Severity; title: string }
  | { type: 'scan.update'; id: string; status: ScanStatus; progress?: number }
  | { type: 'feed.run'; feed_id: string; status: string; items_new?: number }
  | { type: string; [k: string]: unknown };
