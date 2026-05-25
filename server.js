#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3009);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = __dirname;
const INDEX_HTML = path.join(ROOT, 'index.html');
const MIGRATION_CFG_PATH = path.join(ROOT, 'migration.config.json');
const DEFAULT_MIGRATION_CFG = {
  sg: { host: '', port: 4444, username: '', password: '', token: '', api_type: 'utm' },
  xgs: { host: '', port: 5553, username: '', password: '', token: '', api_type: 'xg' },
};
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function ensureMigrationCfgFile() {
  if (!fs.existsSync(MIGRATION_CFG_PATH)) {
    fs.writeFileSync(MIGRATION_CFG_PATH, JSON.stringify(DEFAULT_MIGRATION_CFG, null, 2));
  }
}

function readMigrationCfg() {
  try {
    ensureMigrationCfgFile();
    return JSON.parse(fs.readFileSync(MIGRATION_CFG_PATH, 'utf8'));
  } catch (_) {
    return JSON.parse(JSON.stringify(DEFAULT_MIGRATION_CFG));
  }
}

function writeMigrationCfg(cfg) {
  fs.writeFileSync(MIGRATION_CFG_PATH, JSON.stringify(cfg, null, 2));
}

function mergeMigrationCfg(existing, patch) {
  return {
    sg: { ...(existing.sg || {}), ...((patch && patch.sg) || {}) },
    xgs: { ...(existing.xgs || {}), ...((patch && patch.xgs) || {}) },
  };
}

function normalizeMigrationConn(kind, source = {}) {
  return {
    host: source.host || '',
    port: Number(source.port) || (kind === 'xgs' ? 5553 : 4444),
    username: source.username || '',
    password: source.password || '',
    token: source.token || '',
    api_type: kind === 'xgs' ? 'xg' : 'utm',
  };
}

function migrationConfigResponse(cfg = readMigrationCfg()) {
  return {
    sg: normalizeMigrationConn('sg', cfg.sg),
    xgs: normalizeMigrationConn('xgs', cfg.xgs),
  };
}

function sanitizeXgsName(name, fallback = 'OBJECT') {
  const cleaned = String(name || '')
    .trim()
    .replace(/\s+/g, '_')
    .replace(/[^A-Za-z0-9_.:-]/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 60);
  return cleaned || fallback;
}

function uniqueNameCandidates(...names) {
  return [...new Set(names.flat().filter(Boolean).map(name => sanitizeXgsName(name)))];
}

function sgAuthHeader(cfg) {
  const creds = cfg.token ? `token:${cfg.token}` : `${cfg.username}:${cfg.password}`;
  return `Basic ${Buffer.from(creds).toString('base64')}`;
}

function sgRequest(cfg, method, apiPath, body = null) {
  return new Promise((resolve, reject) => {
    if (!cfg.host) return reject(new Error('SG host is required'));
    const bodyStr = body ? JSON.stringify(body) : '';
    const req = https.request({
      hostname: cfg.host,
      port: cfg.port,
      path: `/api${apiPath}`,
      method,
      rejectUnauthorized: false,
      headers: {
        Authorization: sgAuthHeader(cfg),
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-Restd-Err-Ack': 'all',
        ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
      },
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch (_) { parsed = data; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Request timeout')); });
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

async function sgTestConnection(cfg) {
  try {
    const r = await sgRequest(cfg, 'GET', '/objects/packetfilter/packetfilter/');
    if (r.status === 200 && Array.isArray(r.body)) return { ok: true, host: cfg.host, total_rules: r.body.length };
    if (r.status === 401 || r.status === 403) return { ok: false, error: 'Authentication failed', host: cfg.host };
    return { ok: false, error: `HTTP ${r.status}`, detail: r.body, host: cfg.host };
  } catch (e) {
    return { ok: false, error: e.message, host: cfg.host };
  }
}

function xmlEsc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function xgsRequestWithCfg(cfg, xml) {
  return new Promise((resolve, reject) => {
    if (!cfg.host) return reject(new Error('XGS host is required'));
    const body = 'reqxml=' + encodeURIComponent(`<Request><Login><Username>${xmlEsc(cfg.username || '')}</Username><Password>${xmlEsc(cfg.password || '')}</Password></Login>${xml}</Request>`);
    const req = https.request({
      hostname: cfg.host,
      port: cfg.port,
      path: '/webconsole/APIController',
      method: 'POST',
      rejectUnauthorized: false,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Request timeout')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function xgsParseStatus(xml) {
  const m = xml.match(/<Status code="(\d+)"[^>]*>([\s\S]*?)<\/Status>/i);
  return m ? { code: parseInt(m[1], 10), msg: m[2].trim() } : { code: 0, msg: String(xml || '').slice(0, 200) };
}

async function xgsTestConnection(cfg) {
  try {
    const listed = await xgsListFirewallRules(cfg);
    if (listed.ok) return { ok: true, host: cfg.host, total_rules: listed.rules.length };
    return { ok: false, error: listed.error || 'XGS connection failed', host: cfg.host };
  } catch (e) {
    return { ok: false, error: e.message, host: cfg.host };
  }
}

async function xgsFindHostByIp(cfg, ip) {
  const r = await xgsRequestWithCfg(cfg, '<Get><IPHost></IPHost></Get>');
  const re = /<IPHost(?:\s[^>]*)?>([\s\S]*?)<\/IPHost>/g;
  let m;
  while ((m = re.exec(r.body)) !== null) {
    const block = m[1];
    const name = (block.match(/<Name>(.*?)<\/Name>/) || [])[1] || '';
    const addr = (block.match(/<IPAddress>(.*?)<\/IPAddress>/) || [])[1] || '';
    const start = (block.match(/<StartIPAddress>(.*?)<\/StartIPAddress>/) || [])[1] || '';
    const end = (block.match(/<EndIPAddress>(.*?)<\/EndIPAddress>/) || [])[1] || '';
    if (name && (addr === ip || start === ip || end === ip)) return { ok: true, found: true, name };
  }
  return { ok: true, found: false };
}

async function xgsFindFqdnHost(cfg, hostname) {
  const r = await xgsRequestWithCfg(cfg, '<Get><FQDNHost></FQDNHost></Get>');
  const re = /<FQDNHost(?:\s[^>]*)?>([\s\S]*?)<\/FQDNHost>/g;
  let m;
  while ((m = re.exec(r.body)) !== null) {
    const block = m[1];
    const name = (block.match(/<Name>(.*?)<\/Name>/) || [])[1] || '';
    const fqdn = (block.match(/<FQDN>(.*?)<\/FQDN>/) || [])[1] || '';
    if (name && fqdn && fqdn.toLowerCase() === String(hostname || '').toLowerCase()) return { ok: true, found: true, name };
  }
  return { ok: true, found: false };
}

async function xgsListServices(cfg) {
  const r = await xgsRequestWithCfg(cfg, '<Get><Services></Services></Get>');
  const st = xgsParseStatus(r.body);
  if (!(st.code === 200 || /<Service(?:s)?[>\s]/i.test(r.body))) return { ok: false, error: st.msg || 'XGS service list failed', services: [] };
  const blocks = [];
  for (const re of [/<Service(?:\s[^>]*)?>([\s\S]*?)<\/Service>/g, /<Services(?:\s[^>]*)?>([\s\S]*?)<\/Services>/g]) {
    let m;
    while ((m = re.exec(r.body)) !== null) blocks.push(m[1]);
  }
  const services = [];
  for (const block of blocks) {
    const name = (block.match(/<Name>(.*?)<\/Name>/i) || [])[1] || '';
    const type = (block.match(/<Type>(.*?)<\/Type>/i) || [])[1] || '';
    const proto = (block.match(/<Protocol>(.*?)<\/Protocol>/i) || [])[1] || '';
    const dstPort = (block.match(/<DestinationPort>(.*?)<\/DestinationPort>/i) || [])[1] || '';
    const dport = (block.match(/<DPort>(.*?)<\/DPort>/i) || [])[1] || '';
    if (name) services.push({ name, type, proto, port: dstPort || dport });
  }
  return { ok: true, services };
}

function xgsText(block, tag) {
  const m = String(block || '').match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  return m ? m[1].trim() : '';
}

function xgsTexts(block, parentTag, childTag) {
  const parent = xgsText(block, parentTag);
  if (!parent) return [];
  const re = new RegExp(`<${childTag}>([\\s\\S]*?)<\\/${childTag}>`, 'ig');
  const out = [];
  let m;
  while ((m = re.exec(parent)) !== null) out.push(m[1].trim());
  return out;
}

async function xgsListFirewallRules(cfg) {
  const r = await xgsRequestWithCfg(cfg, '<Get><FirewallRule></FirewallRule></Get>');
  const st = xgsParseStatus(r.body);
  if (!(st.code === 200 || r.body.includes('FirewallRule'))) {
    return { ok: false, error: st.msg || 'XGS connection failed', host: cfg.host, rules: [] };
  }
  const re = /<FirewallRule(?:\s[^>]*)?>([\s\S]*?)<\/FirewallRule>/g;
  const rules = [];
  let m;
  while ((m = re.exec(r.body)) !== null) {
    const block = m[1];
    const name = xgsText(block, 'Name');
    const status = xgsText(block, 'Status');
    const description = xgsText(block, 'Description');
    const action = xgsText(block, 'Action') || xgsText(block, 'RuleAction');
    const sources = xgsTexts(block, 'SourceNetworks', 'Network');
    const destinations = xgsTexts(block, 'DestinationNetworks', 'Network');
    if (!name) continue;
    rules.push({ name, status, description, action, sources, destinations });
  }
  return { ok: true, host: cfg.host, total_rules: rules.length, rules };
}

async function xgsEnsureService(cfg, service) {
  if (!service || !service.name || !service.proto || service.proto === 'any') return { ok: true, name: '' };
  const listed = await xgsListServices(cfg).catch(() => ({ ok: false, services: [] }));
  if (listed.ok) {
    const byName = (listed.services || []).find(s => s.name === service.name);
    if (byName) return { ok: true, name: byName.name, existing: true };
  }
  const proto = String(service.proto || '').toUpperCase();
  const low = parseInt(service.dst_low, 10);
  const high = parseInt(service.dst_high, 10);
  if (!['TCP', 'UDP'].includes(proto) || !low || !high) return { ok: false, error: `Unsupported SG service for migration: ${service.name || service.proto || 'unknown'}` };
  const candidates = uniqueNameCandidates(
    service.name,
    `${service.name}_${proto}_${low}_${high}`,
    `${proto}_${low}_${high}`,
  );
  let last = 'Failed to create service';
  for (const serviceName of candidates) {
    const xml = `<Set operation="add"><Services><Name>${xmlEsc(serviceName)}</Name><Type>${xmlEsc(proto)}</Type><DestinationPort>${xmlEsc(low === high ? String(low) : `${low}:${high}`)}</DestinationPort></Services></Set>`;
    const r = await xgsRequestWithCfg(cfg, xml);
    const st = xgsParseStatus(r.body);
    if (st.code === 200 || /already exists/i.test(st.msg)) return { ok: true, name: serviceName };
    const retry = await xgsListServices(cfg).catch(() => ({ ok: false, services: [] }));
    if (retry.ok) {
      const found = (retry.services || []).find(s => s.name === serviceName);
      if (found) return { ok: true, name: found.name, existing: true };
    }
    last = st.msg || last;
  }
  return { ok: false, error: last };
}

async function xgsEnsureHost(cfg, ip, preferredName = '') {
  const existing = await xgsFindHostByIp(cfg, ip);
  if (existing.ok && existing.found) return { ok: true, name: existing.name, existing: true };
  const ipToken = ip.replace(/[.:]/g, '-');
  const candidates = uniqueNameCandidates(preferredName, `HOST-${ipToken}`, `IP-${ipToken}`);
  let last = 'Unknown error';
  for (const name of candidates) {
    const xml = `<Set operation="add"><IPHost><Name>${xmlEsc(name)}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>${xmlEsc(ip)}</IPAddress></IPHost></Set>`;
    const r = await xgsRequestWithCfg(cfg, xml);
    const st = xgsParseStatus(r.body);
    if (st.code === 200) return { ok: true, name };
    const retry = await xgsFindHostByIp(cfg, ip);
    if (retry.ok && retry.found) return { ok: true, name: retry.name, existing: true };
    last = st.msg;
  }
  return { ok: false, error: last };
}

function prefixToMask(prefix) {
  const p = Number(prefix);
  if (!Number.isInteger(p) || p < 0 || p > 32) return '';
  const parts = [];
  let remain = p;
  for (let i = 0; i < 4; i += 1) {
    const bits = Math.max(0, Math.min(8, remain));
    parts.push(bits ? (256 - Math.pow(2, 8 - bits)) : 0);
    remain -= bits;
  }
  return parts.join('.');
}

async function xgsEnsureNetworkObject(cfg, obj = {}) {
  if (!obj || !obj.kind) return { ok: false, error: 'Missing SG object details' };
  if (obj.kind === 'ip') return xgsEnsureHost(cfg, obj.ip, obj.name || obj.label || obj.ip);
  if (obj.kind === 'fqdn') {
    const existing = await xgsFindFqdnHost(cfg, obj.hostname);
    if (existing.ok && existing.found) return { ok: true, name: existing.name, existing: true };
    const safe = String(obj.hostname || '').replace(/[^a-z0-9.-]+/gi, '-');
    const candidates = uniqueNameCandidates(obj.name, obj.label, safe);
    let last = 'Unknown error';
    for (const name of candidates) {
      const xml = `<Set operation="add"><FQDNHost><Name>${xmlEsc(name)}</Name><FQDN>${xmlEsc(obj.hostname)}</FQDN></FQDNHost></Set>`;
      const r = await xgsRequestWithCfg(cfg, xml);
      const st = xgsParseStatus(r.body);
      if (st.code === 200) return { ok: true, name };
      const retry = await xgsFindFqdnHost(cfg, obj.hostname);
      if (retry.ok && retry.found) return { ok: true, name: retry.name, existing: true };
      last = st.msg;
    }
    return { ok: false, error: last };
  }
  if (obj.kind === 'network') {
    const safe = `${obj.network}/${obj.prefix}`.replace(/[^a-z0-9]+/gi, '-');
    const candidates = uniqueNameCandidates(obj.name, obj.label, `NET-${safe}`);
    let last = 'Unknown error';
    for (const name of candidates) {
      const xml = `<Set operation="add"><IPHost><Name>${xmlEsc(name)}</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType><IPAddress>${xmlEsc(obj.network)}</IPAddress><Subnet>${xmlEsc(obj.mask || prefixToMask(obj.prefix))}</Subnet></IPHost></Set>`;
      const r = await xgsRequestWithCfg(cfg, xml);
      const st = xgsParseStatus(r.body);
      if (st.code === 200) return { ok: true, name };
      last = st.msg;
    }
    return { ok: false, error: last };
  }
  return { ok: false, error: `Unsupported SG object kind: ${obj.kind}` };
}

async function xgsCreateMigratedRule(cfg, { name, action, sourceHost, destinationHost, service, comment }) {
  const sourceXml = sourceHost ? `<SourceNetworks><Network>${xmlEsc(sourceHost)}</Network></SourceNetworks>` : '';
  const destXml = destinationHost ? `<DestinationNetworks><Network>${xmlEsc(destinationHost)}</Network></DestinationNetworks>` : '';
  const serviceXml = service && !/^any$/i.test(String(service)) ? `<Services><Service>${xmlEsc(service)}</Service></Services>` : '';
  const xml = `<Set operation="add"><FirewallRule>` +
    `<Name>${xmlEsc(name)}</Name>` +
    `<Description>${xmlEsc(comment || 'Migrated from Sophos SG')}</Description>` +
    `<IPFamily>IPv4</IPFamily>` +
    `<Status>Enable</Status>` +
    `<Position>Top</Position>` +
    `<PolicyType>Network</PolicyType>` +
    `<NetworkPolicy>` +
      `<Action>${xmlEsc(action === 'accept' ? 'Accept' : 'Drop')}</Action>` +
      `<LogTraffic>Enable</LogTraffic>` +
      `<SkipLocalDestined>Disable</SkipLocalDestined>` +
      `<Schedule>All The Time</Schedule>` +
      `<DSCPMarking>-1</DSCPMarking>` +
      `<WebFilter>None</WebFilter>` +
      `<WebCategoryBaseQoSPolicy> </WebCategoryBaseQoSPolicy>` +
      `<BlockQuickQuic>Disable</BlockQuickQuic>` +
      `<ScanVirus>Disable</ScanVirus>` +
      `<ZeroDayProtection>Disable</ZeroDayProtection>` +
      `<ProxyMode>Disable</ProxyMode>` +
      `<DecryptHTTPS>Disable</DecryptHTTPS>` +
      `<ApplicationControl>None</ApplicationControl>` +
      `<ApplicationBaseQoSPolicy> </ApplicationBaseQoSPolicy>` +
      `<IntrusionPrevention>None</IntrusionPrevention>` +
      `<TrafficShappingPolicy>None</TrafficShappingPolicy>` +
      `<ScanSMTP>Disable</ScanSMTP>` +
      `<ScanSMTPS>Disable</ScanSMTPS>` +
      `<ScanIMAP>Disable</ScanIMAP>` +
      `<ScanIMAPS>Disable</ScanIMAPS>` +
      `<ScanPOP3>Disable</ScanPOP3>` +
      `<ScanPOP3S>Disable</ScanPOP3S>` +
      `<ScanFTP>Disable</ScanFTP>` +
      `<SourceSecurityHeartbeat>Disable</SourceSecurityHeartbeat>` +
      `<MinimumSourceHBPermitted>No Restriction</MinimumSourceHBPermitted>` +
      `<DestSecurityHeartbeat>Disable</DestSecurityHeartbeat>` +
      `<MinimumDestinationHBPermitted>No Restriction</MinimumDestinationHBPermitted>` +
      `${sourceXml}${destXml}${serviceXml}` +
    `</NetworkPolicy>` +
    `</FirewallRule></Set>`;
  const r = await xgsRequestWithCfg(cfg, xml);
  const st = xgsParseStatus(r.body);
  return st.code === 200 || /already exists/i.test(st.msg)
    ? { ok: true, name }
    : { ok: false, error: st.msg || 'Rule create failed', name };
}

function parseIPv4s(values = []) {
  const text = Array.isArray(values) ? values.join(' ') : String(values || '');
  return [...new Set(Array.from(text.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)).map(m => m[1]))];
}

function normalizeSgNetworkObject(obj = {}) {
  if (!obj || typeof obj !== 'object') return null;
  const address = String(obj.address || '').trim();
  const name = String(obj.name || '').trim();
  const ref = String(obj._ref || '').trim();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) {
    const prefix = Number(obj.netmask);
    if (Number.isInteger(prefix) && prefix >= 0 && prefix <= 32) {
      if (prefix === 32) return { ref, name, kind: 'ip', ip: address, label: name || `${address}` };
      return { ref, name, kind: 'network', network: address, prefix, mask: prefixToMask(prefix), label: name || `${address}/${prefix}` };
    }
    return { ref, name, kind: 'ip', ip: address, label: name || `${address}` };
  }
  const hostname = String(obj.hostname || obj.comment || '').trim();
  if (hostname && /[a-z]/i.test(hostname)) {
    return { ref, name, kind: 'fqdn', hostname, label: name || hostname };
  }
  return null;
}

async function sgLoadMigrationData(cfg) {
  const rulesR = await sgRequest(cfg, 'GET', '/objects/packetfilter/packetfilter/');
  if (rulesR.status !== 200) return { ok: false, error: `Failed to load SG rules (HTTP ${rulesR.status})` };
  const [hostsR, netsR, interfaceNetsR, dnsHostsR, dnsGroupsR, anyR, tcpR, udpR] = await Promise.all([
    sgRequest(cfg, 'GET', '/objects/network/host/').catch(() => ({ status: 500, body: [] })),
    sgRequest(cfg, 'GET', '/objects/network/network/').catch(() => ({ status: 500, body: [] })),
    sgRequest(cfg, 'GET', '/objects/network/interface_network/').catch(() => ({ status: 500, body: [] })),
    sgRequest(cfg, 'GET', '/objects/network/dns_host/').catch(() => ({ status: 500, body: [] })),
    sgRequest(cfg, 'GET', '/objects/network/dns_group/').catch(() => ({ status: 500, body: [] })),
    sgRequest(cfg, 'GET', '/objects/service/any/').catch(() => ({ status: 500, body: [] })),
    sgRequest(cfg, 'GET', '/objects/service/tcp/').catch(() => ({ status: 500, body: [] })),
    sgRequest(cfg, 'GET', '/objects/service/udp/').catch(() => ({ status: 500, body: [] })),
  ]);
  const hostObjects = [
    ...(Array.isArray(hostsR.body) ? hostsR.body : []),
    ...(Array.isArray(netsR.body) ? netsR.body : []),
    ...(Array.isArray(interfaceNetsR.body) ? interfaceNetsR.body : []),
    ...(Array.isArray(dnsHostsR.body) ? dnsHostsR.body : []),
    ...(Array.isArray(dnsGroupsR.body) ? dnsGroupsR.body : []),
  ];
  const hostMap = new Map(hostObjects.map(obj => [obj._ref, normalizeSgNetworkObject(obj) || { ref: obj._ref, name: obj.name, kind: 'raw', label: obj.name || String(obj._ref || '') }]));
  const allServices = [
    ...(Array.isArray(anyR.body) ? anyR.body : []).map(s => ({ ...s, proto: 'any' })),
    ...(Array.isArray(tcpR.body) ? tcpR.body : []).map(s => ({ ...s, proto: 'tcp' })),
    ...(Array.isArray(udpR.body) ? udpR.body : []).map(s => ({ ...s, proto: 'udp' })),
  ];
  const serviceMap = new Map(allServices.map(s => [s._ref, { name: s.name, proto: s.proto, dst_low: s.dst_low, dst_high: s.dst_high }]));
  const rules = (Array.isArray(rulesR.body) ? rulesR.body : []).map(rule => {
    const sourceRefs = rule.sources || [];
    const destinationRefs = rule.destinations || [];
    const serviceRefs = rule.services || [];
    const serviceObjs = serviceRefs.map(ref => serviceMap.get(ref) || { name: String(ref || ''), proto: /Any/i.test(String(ref || '')) ? 'any' : 'unknown', rawRef: String(ref || '') });
    const sourceObjects = sourceRefs.map(ref => hostMap.get(ref) || null).filter(Boolean);
    const destinationObjects = destinationRefs.map(ref => hostMap.get(ref) || null).filter(Boolean);
    const anyService = !serviceRefs.length || serviceObjs.some(s => s.proto === 'any' || /Any/i.test(String(s.name || '')) || /REF_ServiceAny/i.test(String(s.rawRef || '')));
    const knownServices = serviceObjs.filter(s => s.proto === 'tcp' || s.proto === 'udp' || s.proto === 'any');
    const specificServices = serviceObjs.filter(s => !(s.proto === 'any' || /Any/i.test(String(s.name || '')) || /REF_ServiceAny/i.test(String(s.rawRef || ''))));
    const serviceNames = serviceObjs.map(s => s.name).filter(Boolean);
    const simpleService = anyService || knownServices.length === 1 || specificServices.length === 1 || serviceRefs.length === 1;
    const sourceAny = !sourceRefs.length || sourceRefs.every(ref => /NetworkAny|Any/i.test(String(ref || '')));
    const destinationAny = !destinationRefs.length || destinationRefs.every(ref => /NetworkAny|Any/i.test(String(ref || '')));
    return {
      name: rule.name,
      action: rule.action,
      enabled: !!rule.status,
      comment: rule.comment || '',
      sourceObjects,
      destinationObjects,
      sourceAny,
      destinationAny,
      anyService,
      simpleService,
      serviceNames,
      serviceDefinition: specificServices.find(s => s.proto === 'tcp' || s.proto === 'udp') || knownServices.find(s => s.proto === 'tcp' || s.proto === 'udp') || knownServices[0] || serviceObjs[0] || null,
      sourceIPs: parseIPv4s(sourceObjects.map(obj => obj.ip || obj.network || obj.label || '')),
      destinationIPs: parseIPv4s(destinationObjects.map(obj => obj.ip || obj.network || obj.label || '')),
    };
  });
  return { ok: true, rules, hostMap, serviceMap, rawHostObjects: hostObjects, rawServices: allServices };
}

function firstRefValue(raw, keys = []) {
  for (const key of keys) {
    const value = raw && raw[key];
    if (Array.isArray(value) && value.length) return value[0];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

async function sgLoadNatData(cfg, hostMap = new Map(), serviceMap = new Map()) {
  const natEndpoints = [
    { kind: 'masq', path: '/objects/nat/masq/' },
    { kind: 'snat', path: '/objects/nat/snat/' },
    { kind: 'dnat', path: '/objects/nat/dnat/' },
    { kind: 'full_nat', path: '/objects/nat/full_nat/' },
    { kind: 'redirect', path: '/objects/nat/redirect/' },
  ];
  const responses = await Promise.all(natEndpoints.map(async entry => {
    try {
      const res = await sgRequest(cfg, 'GET', entry.path);
      return { ...entry, res };
    } catch (error) {
      return { ...entry, res: { status: 500, body: [] }, error };
    }
  }));
  const rules = [];
  for (const { kind, path: endpoint, res } of responses) {
    if (res.status !== 200 || !Array.isArray(res.body)) continue;
    for (const raw of res.body) {
      const sourceRef = firstRefValue(raw, ['source', 'sources', 'src']);
      const destinationRef = firstRefValue(raw, ['destination', 'destinations', 'dst']);
      const serviceRef = firstRefValue(raw, ['service', 'services']);
      const translatedSourceRef = firstRefValue(raw, ['translated_source', 'snat_address', 'nat_address', 'source_translation']);
      const translatedDestinationRef = firstRefValue(raw, ['translated_destination', 'dnat_address', 'destination_translation', 'nat_address']);
      const source = hostMap.get(sourceRef) || null;
      const destination = hostMap.get(destinationRef) || null;
      const translatedSource = hostMap.get(translatedSourceRef) || null;
      const translatedDestination = hostMap.get(translatedDestinationRef) || null;
      const service = serviceMap.get(serviceRef) || null;
      rules.push({
        kind,
        endpoint,
        name: raw.name || `${kind}_${raw._ref || rules.length + 1}`,
        enabled: raw.status !== false,
        comment: raw.comment || '',
        source,
        destination,
        translatedSource,
        translatedDestination,
        service,
        raw,
      });
    }
  }
  return { ok: true, rules };
}

function buildNatPreview(natRules = []) {
  const migratable = [];
  const skipped = [];
  for (const rule of natRules) {
    if (!rule.enabled) {
      skipped.push({ name: rule.name, reason: 'Disabled NAT rule', selectable: false });
      continue;
    }
    if (!['masq', 'snat', 'dnat', 'full_nat', 'redirect'].includes(rule.kind)) {
      skipped.push({ name: rule.name, reason: `Unsupported NAT type: ${rule.kind}`, selectable: false });
      continue;
    }
    migratable.push(rule);
  }
  return { migratable, skipped, total: natRules.length };
}

function buildObjectPreview(sgData = {}, policyPreview = { migratable: [] }, natPreview = { migratable: [] }) {
  const seen = new Map();
  const addObject = (item = {}) => {
    const key = `${item.kind || 'object'}::${item.name || item.label || item.value || 'unknown'}`;
    if (!seen.has(key)) seen.set(key, item);
  };

  for (const raw of (sgData.rawHostObjects || [])) {
    const normalized = normalizeSgNetworkObject(raw);
    addObject({
      name: raw.name || normalized?.label || raw.hostname || raw.address || 'Unnamed object',
      kind: normalized?.kind || raw._type || 'object',
      usage: raw.hostname || raw.address || (Array.isArray(raw.addresses) ? raw.addresses.join(', ') : ''),
    });
  }

  for (const svc of (sgData.rawServices || [])) {
    if (String(svc.name || '').toLowerCase() === 'any' || String(svc._ref || '') === 'REF_ServiceAny') continue;
    addObject({
      name: svc.name || 'Unnamed service',
      kind: 'service',
      usage: `${String(svc.proto || '').toUpperCase() || 'SERVICE'} ${svc.dst_low || ''}${svc.dst_high && svc.dst_high !== svc.dst_low ? `-${svc.dst_high}` : ''}`.trim(),
    });
  }

  for (const rule of (policyPreview.migratable || [])) {
    if (rule.source) addObject({ name: rule.source.name || rule.source.label || rule.source.ip || rule.source.hostname, kind: rule.source.kind, usage: `Policy source: ${rule.name}` });
    if (rule.destination) addObject({ name: rule.destination.name || rule.destination.label || rule.destination.ip || rule.destination.hostname, kind: rule.destination.kind, usage: `Policy destination: ${rule.name}` });
    if (rule.serviceDefinition && rule.serviceDefinition.proto && rule.serviceDefinition.proto !== 'any') addObject({ name: rule.serviceDefinition.name, kind: 'service', usage: `Policy service: ${rule.name}` });
  }
  for (const rule of (natPreview.migratable || [])) {
    if (rule.source) addObject({ name: rule.source.name || rule.source.label || rule.source.ip || rule.source.hostname, kind: rule.source.kind, usage: `NAT source: ${rule.name}` });
    if (rule.destination) addObject({ name: rule.destination.name || rule.destination.label || rule.destination.ip || rule.destination.hostname, kind: rule.destination.kind, usage: `NAT destination: ${rule.name}` });
    if (rule.translatedSource) addObject({ name: rule.translatedSource.name || rule.translatedSource.label || rule.translatedSource.ip || rule.translatedSource.hostname, kind: rule.translatedSource.kind, usage: `NAT translated source: ${rule.name}` });
    if (rule.translatedDestination) addObject({ name: rule.translatedDestination.name || rule.translatedDestination.label || rule.translatedDestination.ip || rule.translatedDestination.hostname, kind: rule.translatedDestination.kind, usage: `NAT translated destination: ${rule.name}` });
    if (rule.service && rule.service.proto && rule.service.proto !== 'any') addObject({ name: rule.service.name, kind: 'service', usage: `NAT service: ${rule.name}` });
  }
  return { migratable: [...seen.values()], skipped: [], total: seen.size };
}

async function xgsCreateNatRule(cfg, natRule = {}) {
  const name = sanitizeXgsName(natRule.name, 'NAT_RULE');
  const description = natRule.comment || `Migrated NAT rule: ${natRule.name}`;
  const sourceName = natRule.sourceName || 'Any';
  const destinationName = natRule.destinationName || 'Any';
  const serviceName = natRule.serviceName || 'Any';
  const translatedSourceName = natRule.translatedSourceName || (natRule.kind === 'masq' ? 'MASQ' : 'Original');
  const translatedDestinationName = natRule.translatedDestinationName || 'Original';
  const typeName = ({ masq: 'MASQ', snat: 'SNAT', dnat: 'DNAT', full_nat: 'FULLNAT', redirect: 'REDIRECT' })[natRule.kind] || 'SNAT';
  const bodies = [
    `<NATRule><Name>${xmlEsc(name)}</Name><Description>${xmlEsc(description)}</Description><Status>Enable</Status><Position>Top</Position><Type>${xmlEsc(typeName)}</Type><OriginalSource>${xmlEsc(sourceName)}</OriginalSource><TranslatedSource>${xmlEsc(translatedSourceName)}</TranslatedSource><OriginalDestination>${xmlEsc(destinationName)}</OriginalDestination><TranslatedDestination>${xmlEsc(translatedDestinationName)}</TranslatedDestination><OriginalService>${xmlEsc(serviceName)}</OriginalService></NATRule>`,
    `<NATPolicy><Name>${xmlEsc(name)}</Name><Description>${xmlEsc(description)}</Description><Status>Enable</Status><Position>Top</Position><PolicyType>${xmlEsc(typeName)}</PolicyType><OriginalSource>${xmlEsc(sourceName)}</OriginalSource><TranslatedSource>${xmlEsc(translatedSourceName)}</TranslatedSource><OriginalDestination>${xmlEsc(destinationName)}</OriginalDestination><TranslatedDestination>${xmlEsc(translatedDestinationName)}</TranslatedDestination><OriginalService>${xmlEsc(serviceName)}</OriginalService></NATPolicy>`,
  ];
  let last = 'NAT create failed';
  for (const body of bodies) {
    const entity = body.startsWith('<NATPolicy>') ? 'NATPolicy' : 'NATRule';
    const xml = `<Set operation="add">${body}</Set>`;
    const r = await xgsRequestWithCfg(cfg, xml);
    const st = xgsParseStatus(r.body);
    if (st.code === 200 || /already exists/i.test(st.msg)) return { ok: true, name, entity };
    last = st.msg || last;
  }
  return { ok: false, error: last, name };
}

function buildMigrationPreview(rules = []) {
  const migratable = [];
  const skipped = [];
  const firstUsable = items => (Array.isArray(items) ? items.find(item => item && ['ip', 'network', 'fqdn'].includes(item.kind)) : null);
  const objectLabel = item => item ? (item.label || item.hostname || item.ip || (item.network && item.prefix !== undefined ? `${item.network}/${item.prefix}` : item.network) || item.name || 'unknown') : '';
  for (const rule of rules) {
    if (!rule.enabled) { skipped.push({ name: rule.name, reason: 'Disabled rule', selectable: false }); continue; }
    if (!['accept', 'drop'].includes(rule.action)) { skipped.push({ name: rule.name, reason: 'Unsupported action', selectable: false }); continue; }
    const sourceObject = firstUsable(rule.sourceObjects);
    const destinationObject = firstUsable(rule.destinationObjects);
    if (rule.sourceAny && rule.destinationAny && rule.anyService) {
      migratable.push({ name: rule.name, action: rule.action, direction: 'any', service: '', serviceDefinition: { name: 'Any', proto: 'any' }, comment: rule.comment, selectable: true });
      continue;
    }
    if (!rule.simpleService) { skipped.push({ name: rule.name, reason: 'Multi-service rule needs review', selectable: false }); continue; }
    if (sourceObject && rule.destinationAny) {
      migratable.push({ name: rule.name, action: rule.action, direction: 'src', source: sourceObject, sourceLabel: objectLabel(sourceObject), ip: sourceObject.ip || sourceObject.network || sourceObject.hostname || '', service: rule.anyService ? '' : ((rule.serviceDefinition && rule.serviceDefinition.name) || rule.serviceNames[0] || ''), serviceDefinition: rule.serviceDefinition, comment: rule.comment, selectable: true });
      continue;
    }
    if (destinationObject && rule.sourceAny) {
      migratable.push({ name: rule.name, action: rule.action, direction: 'dst', destination: destinationObject, destinationLabel: objectLabel(destinationObject), ip: destinationObject.ip || destinationObject.network || destinationObject.hostname || '', service: rule.anyService ? '' : ((rule.serviceDefinition && rule.serviceDefinition.name) || rule.serviceNames[0] || ''), serviceDefinition: rule.serviceDefinition, comment: rule.comment, selectable: true });
      continue;
    }
    if (sourceObject && destinationObject) {
      migratable.push({ name: rule.name, action: rule.action, direction: 'both', source: sourceObject, destination: destinationObject, sourceIp: sourceObject.ip || sourceObject.network || sourceObject.hostname || '', destinationIp: destinationObject.ip || destinationObject.network || destinationObject.hostname || '', sourceLabel: objectLabel(sourceObject), destinationLabel: objectLabel(destinationObject), service: rule.anyService ? '' : ((rule.serviceDefinition && rule.serviceDefinition.name) || rule.serviceNames[0] || ''), serviceDefinition: rule.serviceDefinition, comment: rule.comment, selectable: true });
      continue;
    }
    skipped.push({ name: rule.name, reason: 'Only single host, subnet, or FQDN source/destination rules migrate automatically', selectable: false });
  }
  return { migratable, skipped, total: rules.length };
}

async function runMigration(sourceCfg, targetCfg, selectedRuleNames = []) {
  const sgData = await sgLoadMigrationData(sourceCfg);
  if (!sgData.ok) return sgData;
  const natData = await sgLoadNatData(sourceCfg, sgData.hostMap, sgData.serviceMap);
  const preview = buildMigrationPreview(sgData.rules);
  const natPreview = buildNatPreview((natData && natData.rules) || []);
  const objectPreview = buildObjectPreview(sgData, preview, natPreview);
  const selected = new Set((Array.isArray(selectedRuleNames) && selectedRuleNames.length ? selectedRuleNames : preview.migratable.map(item => item.name)).filter(Boolean));
  const chosen = preview.migratable.filter(item => selected.has(item.name));
  const skippedByChoice = preview.migratable.filter(item => !selected.has(item.name)).map(item => ({ name: item.name, reason: 'Not selected for migration' }));
  const applied = [];
  const failed = [];
  const objects = { ensured: [], failed: [] };
  const nat = { applied: [], failed: [], skipped: natPreview.skipped };
  for (const item of chosen) {
    let sourceHost = '';
    let destinationHost = '';
    const primaryIp = item.ip || item.sourceIp || item.destinationIp || item.sourceLabel || item.destinationLabel || '';
    if (item.direction === 'src' || item.direction === 'both') {
      const ensured = await xgsEnsureNetworkObject(targetCfg, item.direction === 'both' ? item.source : (item.source || { kind: 'ip', ip: item.ip }));
      if (!ensured.ok) { failed.push({ name: item.name, ip: primaryIp, error: ensured.error }); continue; }
      sourceHost = ensured.name;
      objects.ensured.push({ rule: item.name, kind: 'source', sourceName: item.source?.name || item.sourceLabel || item.ip, xgsName: ensured.name, existing: !!ensured.existing });
    }
    if (item.direction === 'dst' || item.direction === 'both') {
      const ensured = await xgsEnsureNetworkObject(targetCfg, item.direction === 'both' ? item.destination : (item.destination || { kind: 'ip', ip: item.ip }));
      if (!ensured.ok) { failed.push({ name: item.name, ip: primaryIp, error: ensured.error }); continue; }
      destinationHost = ensured.name;
      objects.ensured.push({ rule: item.name, kind: 'destination', sourceName: item.destination?.name || item.destinationLabel || item.ip, xgsName: ensured.name, existing: !!ensured.existing });
    }
    let xgsServiceName = item.service || '';
    if (item.serviceDefinition && item.serviceDefinition.proto && item.serviceDefinition.proto !== 'any') {
      const ensuredService = await xgsEnsureService(targetCfg, item.serviceDefinition);
      if (!ensuredService.ok) { failed.push({ name: item.name, ip: primaryIp, error: ensuredService.error }); continue; }
      xgsServiceName = ensuredService.name;
      objects.ensured.push({ rule: item.name, kind: 'service', sourceName: item.serviceDefinition.name, xgsName: ensuredService.name, existing: !!ensuredService.existing });
    }
    const ruleName = item.name;
    const created = await xgsCreateMigratedRule(targetCfg, {
      name: ruleName,
      action: item.action,
      sourceHost,
      destinationHost,
      service: xgsServiceName || '',
      comment: item.comment || '',
    });
    if (created.ok) applied.push({ sourceRule: item.name, targetRule: ruleName, ip: primaryIp, sourceIp: item.sourceIp, destinationIp: item.destinationIp, sourceLabel: item.sourceLabel, destinationLabel: item.destinationLabel, direction: item.direction, action: item.action, service: xgsServiceName || '' });
    else failed.push({ name: item.name, ip: primaryIp, error: created.error });
  }
  for (const item of natPreview.migratable) {
    try {
      let sourceName = 'Any';
      let destinationName = 'Any';
      let translatedSourceName = '';
      let translatedDestinationName = '';
      let serviceName = '';
      if (item.source) {
        const ensured = await xgsEnsureNetworkObject(targetCfg, item.source);
        if (!ensured.ok) throw new Error(`NAT source object failed: ${ensured.error}`);
        sourceName = ensured.name;
      }
      if (item.destination) {
        const ensured = await xgsEnsureNetworkObject(targetCfg, item.destination);
        if (!ensured.ok) throw new Error(`NAT destination object failed: ${ensured.error}`);
        destinationName = ensured.name;
      }
      if (item.translatedSource) {
        const ensured = await xgsEnsureNetworkObject(targetCfg, item.translatedSource);
        if (!ensured.ok) throw new Error(`Translated source object failed: ${ensured.error}`);
        translatedSourceName = ensured.name;
      }
      if (item.translatedDestination) {
        const ensured = await xgsEnsureNetworkObject(targetCfg, item.translatedDestination);
        if (!ensured.ok) throw new Error(`Translated destination object failed: ${ensured.error}`);
        translatedDestinationName = ensured.name;
      }
      if (item.service && item.service.proto && item.service.proto !== 'any') {
        const ensuredService = await xgsEnsureService(targetCfg, item.service);
        if (!ensuredService.ok) throw new Error(`NAT service failed: ${ensuredService.error}`);
        serviceName = ensuredService.name;
      }
      const created = await xgsCreateNatRule(targetCfg, {
        ...item,
        sourceName,
        destinationName,
        translatedSourceName,
        translatedDestinationName,
        serviceName,
      });
      if (!created.ok) throw new Error(created.error);
      nat.applied.push({ sourceRule: item.name, targetRule: created.name, kind: item.kind });
    } catch (error) {
      nat.failed.push({ name: item.name, kind: item.kind, error: error.message || String(error) });
    }
  }
  let visibility = { verified: [], missing: [], total_visible_rules: 0 };
  try {
    const listed = await xgsListFirewallRules(targetCfg);
    if (listed.ok) {
      const names = new Set((listed.rules || []).map(r => r.name));
      visibility = {
        verified: applied.filter(item => names.has(item.targetRule)).map(item => item.targetRule),
        missing: applied.filter(item => !names.has(item.targetRule)).map(item => item.targetRule),
        total_visible_rules: (listed.rules || []).length,
      };
      applied.forEach(item => { item.visible = names.has(item.targetRule); });
    } else {
      visibility = { verified: [], missing: applied.map(item => item.targetRule), total_visible_rules: 0, error: listed.error || 'Unable to reload XGS rules' };
    }
  } catch (e) {
    visibility = { verified: [], missing: applied.map(item => item.targetRule), total_visible_rules: 0, error: e.message || String(e) };
  }
  return { ok: true, preview: { ...preview, skipped: [...preview.skipped, ...skippedByChoice] }, objectPreview, natPreview, applied, failed, objects, nat, visibility, selected: [...selected] };
}

function readJson(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch (_) { resolve({}); }
    });
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
  res.end(JSON.stringify(data, null, 2));
}

ensureMigrationCfgFile();

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS);
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);

  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    try {
      const html = fs.readFileSync(INDEX_HTML, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(e.message);
    }
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    return sendJson(res, 200, { ok: true, app: 'sophos-integration', port: PORT });
  }

  if (url.pathname.startsWith('/migration')) {
    const sub = url.pathname.slice('/migration'.length) || '/';

    if (sub === '/config' && req.method === 'GET') {
      return sendJson(res, 200, { ok: true, config: migrationConfigResponse() });
    }

    if (sub === '/config' && req.method === 'POST') {
      const p = await readJson(req);
      const next = mergeMigrationCfg(readMigrationCfg(), {
        sg: normalizeMigrationConn('sg', p.sg || {}),
        xgs: normalizeMigrationConn('xgs', p.xgs || {}),
      });
      writeMigrationCfg(next);
      return sendJson(res, 200, { ok: true, config: migrationConfigResponse(next) });
    }

    if (sub === '/test-sg' && req.method === 'POST') {
      const p = await readJson(req);
      const saved = readMigrationCfg();
      const result = await sgTestConnection(normalizeMigrationConn('sg', { ...(saved.sg || {}), ...((p && p.sg) || {}) }));
      return sendJson(res, result.ok ? 200 : 503, result);
    }

    if (sub === '/test-xgs' && req.method === 'POST') {
      const p = await readJson(req);
      const saved = readMigrationCfg();
      const result = await xgsTestConnection(normalizeMigrationConn('xgs', { ...(saved.xgs || {}), ...((p && p.xgs) || {}) }));
      return sendJson(res, result.ok ? 200 : 503, result);
    }

    if (sub === '/xgs-rules' && req.method === 'POST') {
      try {
        const p = await readJson(req);
        const saved = readMigrationCfg();
        const xgsCfg = normalizeMigrationConn('xgs', { ...(saved.xgs || {}), ...((p && p.xgs) || {}) });
        const result = await xgsListFirewallRules(xgsCfg);
        return sendJson(res, result.ok ? 200 : 503, result);
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: e.message || String(e), rules: [] });
      }
    }

    if (sub === '/preview' && req.method === 'POST') {
      try {
        const p = await readJson(req);
        const saved = readMigrationCfg();
        const sgCfg = normalizeMigrationConn('sg', { ...(saved.sg || {}), ...((p && p.sg) || {}) });
        const loaded = await sgLoadMigrationData(sgCfg);
        if (!loaded.ok) return sendJson(res, 500, loaded);
        const natData = await sgLoadNatData(sgCfg, loaded.hostMap, loaded.serviceMap);
        const preview = buildMigrationPreview(loaded.rules);
        const natPreview = buildNatPreview((natData && natData.rules) || []);
        const objectPreview = buildObjectPreview(loaded, preview, natPreview);
        return sendJson(res, 200, { ok: true, preview, objectPreview, natPreview });
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: e.message || String(e) });
      }
    }

    if (sub === '/run' && req.method === 'POST') {
      try {
        const p = await readJson(req);
        const saved = readMigrationCfg();
        const sgCfg = normalizeMigrationConn('sg', { ...(saved.sg || {}), ...((p && p.sg) || {}) });
        const xgsCfg = normalizeMigrationConn('xgs', { ...(saved.xgs || {}), ...((p && p.xgs) || {}) });
        const result = await runMigration(sgCfg, xgsCfg, (p && p.selectedRules) || []);
        return sendJson(res, result.ok ? 200 : 500, result);
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: e.message || String(e) });
      }
    }
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...CORS });
  res.end('Not found');
});

server.listen(PORT, HOST, () => {
  console.log(`Sophos Integration running at http://${HOST}:${PORT}/`);
  console.log(`Config file: ${MIGRATION_CFG_PATH}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
