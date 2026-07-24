-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Seed 0009: RBAC roles/permissions, MITRE tactics, default feeds
-- Idempotent (ON CONFLICT DO NOTHING / UPDATE).
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ── Permissions ──────────────────────────────────────────────────────────────
INSERT INTO aegis.permissions(code, description) VALUES
  ('ioc:read','View indicators'),
  ('ioc:write','Create/edit indicators'),
  ('ioc:delete','Delete indicators'),
  ('cve:read','View vulnerabilities'),
  ('rule:read','View detection rules'),
  ('rule:write','Create/edit detection rules'),
  ('scan:read','View scans'),
  ('scan:run','Launch scans'),
  ('feed:read','View feeds'),
  ('feed:manage','Configure feeds'),
  ('alert:read','View alerts'),
  ('alert:manage','Acknowledge/resolve alerts, edit rules'),
  ('asset:read','View assets'),
  ('asset:write','Manage assets'),
  ('user:read','View users'),
  ('user:manage','Manage users and roles'),
  ('audit:read','View audit log'),
  ('search:read','Use unified search')
ON CONFLICT (code) DO NOTHING;

-- ── Roles ────────────────────────────────────────────────────────────────────
INSERT INTO aegis.roles(name, description, is_system) VALUES
  ('admin','Full administrative access', true),
  ('analyst','SOC analyst: read all, manage IOCs/rules/scans/alerts', true),
  ('viewer','Read-only access', true)
ON CONFLICT (name) DO NOTHING;

-- admin → all permissions
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r CROSS JOIN aegis.permissions p
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

-- analyst → everything except user:manage and feed:manage
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name = 'analyst'
  AND p.code IN ('ioc:read','ioc:write','ioc:delete','cve:read','rule:read','rule:write',
                 'scan:read','scan:run','feed:read','alert:read','alert:manage',
                 'asset:read','asset:write','search:read')
ON CONFLICT DO NOTHING;

-- viewer → all *:read + search
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name = 'viewer' AND (p.code LIKE '%:read')
ON CONFLICT DO NOTHING;

-- ── MITRE ATT&CK Enterprise tactics (14) ─────────────────────────────────────
INSERT INTO aegis.mitre_tactics(id, name, shortname, sort_order) VALUES
  ('TA0043','Reconnaissance','reconnaissance',1),
  ('TA0042','Resource Development','resource-development',2),
  ('TA0001','Initial Access','initial-access',3),
  ('TA0002','Execution','execution',4),
  ('TA0003','Persistence','persistence',5),
  ('TA0004','Privilege Escalation','privilege-escalation',6),
  ('TA0005','Defense Evasion','defense-evasion',7),
  ('TA0006','Credential Access','credential-access',8),
  ('TA0007','Discovery','discovery',9),
  ('TA0008','Lateral Movement','lateral-movement',10),
  ('TA0009','Collection','collection',11),
  ('TA0011','Command and Control','command-and-control',12),
  ('TA0010','Exfiltration','exfiltration',13),
  ('TA0040','Impact','impact',14)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, sort_order = EXCLUDED.sort_order;

-- ── Default threat feeds (disabled until keys configured) ────────────────────
INSERT INTO aegis.feeds(name, provider, url, format, enabled, interval_secs, default_tlp) VALUES
  ('CISA KEV','cisa_kev','https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json','json',true,86400,'clear'),
  ('EPSS','epss','https://epss.cyentia.com/epss_scores-current.csv.gz','csv',true,86400,'clear'),
  ('URLhaus','urlhaus','https://urlhaus.abuse.ch/downloads/csv_recent/','csv',true,3600,'clear'),
  ('Feodo Tracker','feodo','https://feodotracker.abuse.ch/downloads/ipblocklist.json','json',true,3600,'clear'),
  ('NVD CVE 2.0','nvd','https://services.nvd.nist.gov/rest/json/cves/2.0','json',true,21600,'clear'),
  ('MITRE ATT&CK','mitre','https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json','json',true,604800,'clear'),
  ('MalwareBazaar','malwarebazaar','https://mb-api.abuse.ch/api/v1/','json',false,3600,'clear'),
  ('AlienVault OTX','otx','https://otx.alienvault.com/api/v1/pulses/subscribed','json',false,3600,'green')
ON CONFLICT (name) DO NOTHING;

-- ── Starter detection rules (YARA + Sigma) ───────────────────────────────────
-- Small, valid, illustrative rules so the Detections module is populated on a
-- fresh install. is_valid is left NULL here; the API re-validates on edit.
INSERT INTO aegis.detection_rules
  (format, name, rule_id_ext, content, description, author, severity, status, tags, technique_ids, is_enabled)
VALUES
  ('yara','EICAR_Test_File',NULL,
   E'rule EICAR_Test_File\n{\n  meta:\n    description = "EICAR antivirus test string"\n  strings:\n    $eicar = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"\n  condition:\n    $eicar\n}',
   'Detects the standard EICAR AV test file.','aegis','info','stable',
   ARRAY['test','eicar']::text[], ARRAY[]::text[], true),
  ('sigma','Suspicious PowerShell EncodedCommand','a1b2c3d4-0000-4000-8000-000000000001',
   E'title: Suspicious PowerShell EncodedCommand\nid: a1b2c3d4-0000-4000-8000-000000000001\nstatus: experimental\ntags:\n    - attack.execution\n    - attack.t1059.001\ndetection:\n    selection:\n        Image|endswith: ''\\powershell.exe''\n        CommandLine|contains: ''-EncodedCommand''\n    condition: selection\nlevel: high',
   'Flags PowerShell launched with -EncodedCommand (common obfuscation).','aegis','high','test',
   ARRAY['powershell','obfuscation']::text[], ARRAY['T1059.001']::text[], true)
ON CONFLICT (format, name) DO NOTHING;
