import type { FastifyInstance } from 'fastify';
import { pool } from '../db/pool.js';
const ANALYZER_URL = process.env.ANALYZER_URL ?? 'http://analyzer:7000';
const MAX = 64 * 1024 * 1024;
export default async function pcaps(app: FastifyInstance): Promise<void> {
  app.get('/', { preHandler:[app.requirePerms('pcap:read')] }, async () => ({ data:(await pool.query(`SELECT id,sha256,size_bytes,format,packet_count,duration_ms,interface_count,top_talkers,protocol_mix,dns_queries,tls_snis,http_hosts,suspicious,ioc_matches,score,summary,requested_by,created_at FROM aegis.pcap_analyses ORDER BY created_at DESC LIMIT 100`)).rows }));
  app.get('/:id', { preHandler:[app.requirePerms('pcap:read')] }, async (req, reply) => { const {id}=req.params as {id:string}; const a=(await pool.query(`SELECT id,sha256,size_bytes,format,packet_count,duration_ms,interface_count,top_talkers,protocol_mix,dns_queries,tls_snis,http_hosts,suspicious,ioc_matches,score,summary,requested_by,created_at FROM aegis.pcap_analyses WHERE id=$1`,[id])).rows[0]; if(!a)return reply.code(404).send({error:'not_found'}); return {...a,findings:(await pool.query(`SELECT id,finding_id,severity,title,detail,created_at FROM aegis.pcap_findings WHERE analysis_id=$1 ORDER BY id`,[id])).rows}; });
  app.delete('/:id', { preHandler:[app.requirePerms('pcap:run')] }, async (req, reply) => { await pool.query('DELETE FROM aegis.pcap_analyses WHERE id=$1',[(req.params as {id:string}).id]); return reply.code(204).send(); });
  app.post('/', { preHandler:[app.requirePerms('pcap:run')] }, async (req, reply) => {
    const file = await (req as any).file({limits:{fileSize:MAX}}); if(!file)return reply.code(400).send({error:'no_file'});
    let bytes:Buffer; try { bytes=await file.toBuffer(); } catch { return reply.code(413).send({error:'file_too_large'}); }
    if(file.file.truncated || !bytes.length)return reply.code(file.file.truncated?413:400).send({error:file.file.truncated?'file_too_large':'empty_file'});
    const iocs=(await pool.query(`SELECT value FROM aegis.iocs WHERE is_active=true AND type IN ('ipv4','ipv6','domain','url') LIMIT 50000`)).rows.map(x=>x.value);
    const res=await fetch(`${ANALYZER_URL}/analyze/pcap`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capture_base64:bytes.toString('base64'),iocs})}); if(!res.ok)return reply.code(502).send({error:'analyzer_error'}); const r:any=await res.json();
    const row=(await pool.query(`INSERT INTO aegis.pcap_analyses(sha256,size_bytes,format,packet_count,duration_ms,interface_count,top_talkers,protocol_mix,dns_queries,tls_snis,http_hosts,suspicious,ioc_matches,score,summary,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(sha256) DO UPDATE SET updated_at=now(),score=EXCLUDED.score,summary=EXCLUDED.summary RETURNING id,sha256,score`,[r.sha256,r.size_bytes,r.format,r.packet_count,r.duration_ms,r.interface_count,r.top_talkers,r.protocol_mix,r.dns_queries,r.tls_snis,r.http_hosts,r.suspicious,r.ioc_matches,r.score,r.summary,req.user.sub])).rows[0];
    for(const f of r.findings??[]) await pool.query(`INSERT INTO aegis.pcap_findings(analysis_id,finding_id,severity,title,detail) VALUES($1,$2,$3::aegis.severity,$4,$5)`,[row.id,f.finding_id,f.severity,f.title,f.detail]); return row;
  });
}
