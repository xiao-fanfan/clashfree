import fetch from 'node-fetch';
import yaml from 'js-yaml';
import net from 'node:net';
import { Buffer } from 'node:buffer';

// 免费节点来源。Vercel 免费版函数执行时间有限，因此源数量保持克制。
const SOURCES = [
  'https://raw.githubusercontent.com/freefq/free/master/v2',
  'https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml',
  'https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt',
];

// 节点延迟上限，超过 2000ms 或不可连接的节点会被过滤。
const MAX_LATENCY_MS = 2000;

// 并发数太高会触发 Vercel 免费版资源限制，这里保守限制。
const TEST_CONCURRENCY = 20;

// 6 小时缓存，减少 Vercel 免费额度消耗，也让 Shadowrocket 自动更新更稳定。
const CACHE_SECONDS = 21600;

function send(res, statusCode, body, contentType = 'text/plain; charset=utf-8') {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', contentType);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', `public, max-age=${CACHE_SECONDS}, s-maxage=${CACHE_SECONDS}`);
  res.end(body);
}

function safeBase64Decode(text) {
  const compact = String(text || '').replace(/\s+/g, '');
  if (!compact) return '';
  try {
    const padded = compact + '='.repeat((4 - (compact.length % 4)) % 4);
    return Buffer.from(padded, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function safeBase64Encode(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

function cleanName(value, fallback) {
  const raw = decodeURIComponent(String(value || '')).trim() || fallback;
  return raw.replace(/[\r\n\t]+/g, ' ').slice(0, 120);
}

function toInt(value) {
  const number = Number.parseInt(value, 10);
  return Number.isFinite(number) ? number : 0;
}

function renameProxiesSequentially(proxies) {
  return proxies.map((proxy, index) => ({
    ...proxy,
    name: `节点-${String(index + 1).padStart(3, '0')}`,
  }));
}

function parseVmess(line) {
  const decoded = safeBase64Decode(line.replace('vmess://', ''));
  if (!decoded) return null;
  try {
    const item = JSON.parse(decoded);
    const server = item.add;
    const port = toInt(item.port);
    if (!server || !port || !item.id) return null;

    const proxy = {
      name: cleanName(item.ps, `vmess-${server}:${port}`),
      type: 'vmess',
      server,
      port,
      uuid: item.id,
      alterId: toInt(item.aid),
      cipher: item.scy || 'auto',
      udp: true,
      raw: line,
    };

    if (item.net) proxy.network = item.net;
    if (String(item.tls || '').toLowerCase() === 'tls') {
      proxy.tls = true;
      if (item.sni) proxy.servername = item.sni;
    }
    if (item.net === 'ws') {
      proxy['ws-opts'] = {
        path: item.path || '/',
        headers: item.host ? { Host: item.host } : {},
      };
    }
    return proxy;
  } catch {
    return null;
  }
}

function parseSS(line) {
  try {
    let raw = line.replace('ss://', '');
    let name = 'ss-node';
    if (raw.includes('#')) {
      const parts = raw.split('#');
      raw = parts[0];
      name = cleanName(parts.slice(1).join('#'), name);
    }
    if (raw.includes('?')) raw = raw.split('?')[0];
    if (!raw.includes('@')) raw = safeBase64Decode(raw);
    if (!raw.includes('@')) return null;

    let [userinfo, endpoint] = raw.split('@');
    if (!userinfo.includes(':')) userinfo = safeBase64Decode(userinfo) || userinfo;
    if (endpoint.includes('?')) endpoint = endpoint.split('?')[0];
    if (!userinfo.includes(':') || !endpoint.includes(':')) return null;

    const [cipher, password] = userinfo.split(/:(.*)/s);
    const [server, portText] = endpoint.split(/:(\d+)$/);
    const port = toInt(portText);
    if (!server || !port) return null;

    return {
      name,
      type: 'ss',
      server,
      port,
      cipher: decodeURIComponent(cipher),
      password: decodeURIComponent(password),
      udp: true,
      raw: line,
    };
  } catch {
    return null;
  }
}

function parseTrojan(line) {
  try {
    const url = new URL(line);
    const port = toInt(url.port);
    if (!url.hostname || !port || !url.username) return null;
    return {
      name: cleanName(url.hash.replace('#', ''), `trojan-${url.hostname}:${port}`),
      type: 'trojan',
      server: url.hostname,
      port,
      password: decodeURIComponent(url.username),
      sni: url.searchParams.get('sni') || url.searchParams.get('peer') || url.hostname,
      'skip-cert-verify': ['1', 'true'].includes(url.searchParams.get('allowInsecure') || ''),
      udp: true,
      raw: line,
    };
  } catch {
    return null;
  }
}

function parseVless(line) {
  try {
    const url = new URL(line);
    const port = toInt(url.port);
    if (!url.hostname || !port || !url.username) return null;
    const proxy = {
      name: cleanName(url.hash.replace('#', ''), `vless-${url.hostname}:${port}`),
      type: 'vless',
      server: url.hostname,
      port,
      uuid: decodeURIComponent(url.username),
      udp: true,
      tls: url.searchParams.get('security') === 'tls',
      servername: url.searchParams.get('sni') || url.searchParams.get('host') || url.hostname,
      raw: line,
    };
    const network = url.searchParams.get('type');
    if (network) proxy.network = network;
    if (network === 'ws') {
      proxy['ws-opts'] = {
        path: url.searchParams.get('path') || '/',
        headers: { Host: url.searchParams.get('host') || url.hostname },
      };
    }
    return proxy;
  } catch {
    return null;
  }
}

function parseLine(line) {
  const text = line.trim();
  if (text.startsWith('vmess://')) return parseVmess(text);
  if (text.startsWith('ss://')) return parseSS(text);
  if (text.startsWith('trojan://')) return parseTrojan(text);
  if (text.startsWith('vless://')) return parseVless(text);
  return null;
}

function extractYamlProxies(text) {
  try {
    const data = yaml.load(text);
    if (Array.isArray(data)) return data.filter((item) => item && typeof item === 'object');
    if (data && Array.isArray(data.proxies)) return data.proxies.filter((item) => item && typeof item === 'object');
  } catch {
    // YAML 解析失败时继续按订阅文本处理。
  }
  return [];
}

function parseContent(text) {
  const proxies = [...extractYamlProxies(text)];
  const decoded = safeBase64Decode(text);
  const lines = text.split(/\r?\n/);
  if (decoded) {
    proxies.push(...extractYamlProxies(decoded));
    lines.push(...decoded.split(/\r?\n/));
  }

  for (const line of lines) {
    const proxy = parseLine(line);
    if (proxy) proxies.push(proxy);
  }
  return proxies;
}

async function fetchText(url) {
  try {
    const response = await fetch(url, {
      timeout: 12000,
      headers: { 'User-Agent': 'substore-vercel/1.0' },
    });
    if (!response.ok) return '';
    return await response.text();
  } catch {
    return '';
  }
}

function dedupe(proxies) {
  const seen = new Set();
  const result = [];
  for (const proxy of proxies) {
    const server = String(proxy.server || '').trim();
    const port = toInt(proxy.port);
    if (!server || !port || !proxy.type) continue;
    const key = `${server}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ ...proxy, server, port });
  }
  return result;
}

function testLatency(proxy) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = net.createConnection({ host: proxy.server, port: proxy.port, timeout: MAX_LATENCY_MS });

    const done = (latency) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(latency);
    };

    socket.once('connect', () => done(Date.now() - start));
    socket.once('timeout', () => done(null));
    socket.once('error', () => done(null));
  });
}

async function mapWithConcurrency(items, limit, mapper) {
  const result = [];
  let index = 0;
  async function worker() {
    while (index < items.length) {
      const current = index;
      index += 1;
      result[current] = await mapper(items[current]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return result;
}

async function getCleanNodes() {
  const texts = await Promise.all(SOURCES.map(fetchText));
  const parsed = dedupe(texts.flatMap(parseContent));

  // Vercel 免费版执行时间有限，节点过多时只测试前 250 个候选，避免函数超时。
  const candidates = parsed.slice(0, 250);
  const tested = await mapWithConcurrency(candidates, TEST_CONCURRENCY, async (proxy) => {
    const latency = await testLatency(proxy);
    if (latency === null || latency > MAX_LATENCY_MS) return null;
    return { ...proxy, latency };
  });

  return tested.filter(Boolean).sort((a, b) => a.latency - b.latency);
}

function stripRuntimeFields(proxy) {
  const { raw, latency, ...clean } = proxy;
  return clean;
}

function encodeSubscription(proxies) {
  const lines = proxies.map((proxy) => proxy.raw).filter(Boolean);
  return safeBase64Encode(lines.join('\n'));
}

function buildClashYaml(proxies) {
  const cleanProxies = renameProxiesSequentially(proxies.map(stripRuntimeFields));
  const names = cleanProxies.map((item) => item.name);
  const config = {
    'mixed-port': 7890,
    'allow-lan': true,
    mode: 'rule',
    'log-level': 'info',
    dns: {
      enable: true,
      listen: '0.0.0.0:1053',
      ipv6: false,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      'default-nameserver': ['223.5.5.5', '119.29.29.29'],
      nameserver: ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
      fallback: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
      'fallback-filter': { geoip: true, 'geoip-code': 'CN' },
    },
    proxies: cleanProxies,
    'proxy-groups': [
      {
        name: 'AUTO',
        type: 'url-test',
        proxies: names.length ? names : ['DIRECT'],
        url: 'https://www.gstatic.com/generate_204',
        interval: 300,
        tolerance: 80,
      },
      { name: 'PROXY', type: 'select', proxies: ['AUTO', 'DIRECT', ...names] },
    ],
    rules: ['DOMAIN-SUFFIX,cn,DIRECT', 'GEOIP,CN,DIRECT', 'MATCH,PROXY'],
  };
  return yaml.dump(config, { lineWidth: -1 });
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, '');
  if (req.method !== 'GET') return send(res, 405, 'Method Not Allowed');

  try {
    const pathname = new URL(req.url, 'https://example.com').pathname;
    const nodes = await getCleanNodes();

    if (pathname === '/clash') {
      return send(res, 200, buildClashYaml(nodes), 'application/x-yaml; charset=utf-8');
    }

    if (pathname === '/shadowrocket' || pathname === '/all' || pathname === '/') {
      return send(res, 200, encodeSubscription(nodes), 'text/plain; charset=utf-8');
    }

    return send(res, 404, 'Not Found');
  } catch (error) {
    return send(res, 500, `Sub-Store error: ${error.message}`);
  }
}
