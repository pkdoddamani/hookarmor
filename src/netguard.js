const net = require('net');
const dns = require('dns');

// Outbound address policy for delivery targets and alert webhooks.
// 'metadata' addresses are always blocked; 'private' ones only in strict mode.

function parseIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  return octets.every((o) => Number.isInteger(o) && o >= 0 && o <= 255) ? octets : null;
}

// Expand an IPv6 address (with optional embedded IPv4 tail) into 8 16-bit groups
function parseIPv6(ip) {
  let addr = ip.replace(/^\[|\]$/g, '').split('%')[0];
  const v4Tail = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Tail) {
    const o = parseIPv4(v4Tail[1]);
    if (!o) return null;
    addr = addr.slice(0, -v4Tail[1].length) + `${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = addr.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const groups = [...head, ...Array(fill).fill('0'), ...tail].map((g) => parseInt(g, 16));
  return groups.length === 8 && groups.every((g) => g >= 0 && g <= 0xffff) ? groups : null;
}

function classifyIPv4([a, b, c, d]) {
  if (a === 169 && b === 254) return 'metadata'; // link-local, incl. AWS/GCP/Azure metadata
  if (a === 100 && b === 100 && c === 100 && d === 200) return 'metadata'; // Alibaba metadata
  if (
    a === 0 || a === 10 || a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224 // multicast, reserved, broadcast
  ) return 'private';
  return 'public';
}

function classifyIp(ip) {
  const host = ip.replace(/^\[|\]$/g, '');
  if (net.isIPv4(host)) return classifyIPv4(parseIPv4(host));
  if (!net.isIPv6(host)) return 'invalid';
  const g = parseIPv6(host);
  if (!g) return 'invalid';
  const v4 = [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
  // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96) carry an IPv4 address
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return classifyIPv4(v4);
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return classifyIPv4(v4);
  if (g[0] === 0xfd00 && g[1] === 0x0ec2 && g.slice(2, 7).every((x) => x === 0) && g[7] === 0x254) return 'metadata'; // AWS IMDS IPv6
  if (g.every((x) => x === 0)) return 'private'; // ::
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return 'private'; // ::1
  if ((g[0] & 0xfe00) === 0xfc00) return 'private'; // fc00::/7 unique local
  if ((g[0] & 0xffc0) === 0xfe80) return 'private'; // fe80::/10 link-local
  if ((g[0] & 0xff00) === 0xff00) return 'private'; // multicast
  return 'public';
}

function isBlockedIp(ip, strict) {
  const cls = classifyIp(ip);
  return cls === 'invalid' || cls === 'metadata' || (strict && cls === 'private');
}

// Synchronous check of the URL itself (scheme, literal IPs, well-known internal names).
// Hostnames are re-checked after DNS resolution at request time via guardedLookup().
function checkUrl(urlString, strict = false) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch (e) {
    return { ok: false, reason: 'Invalid URL' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, reason: 'Only http and https URLs are allowed' };
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    return isBlockedIp(host, strict) ? { ok: false, reason: `Address ${host} is not allowed` } : { ok: true };
  }
  if (host === 'metadata.google.internal' || host === 'metadata') {
    return { ok: false, reason: `Host ${host} is not allowed` };
  }
  if (strict && (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local'))) {
    return { ok: false, reason: `Host ${host} is not allowed` };
  }
  return { ok: true };
}

// DNS lookup for http.request that refuses blocked addresses, so a public hostname
// cannot resolve (or re-resolve) to an internal address at delivery time.
function guardedLookup(strict = false) {
  return (hostname, options, callback) => {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    dns.lookup(hostname, options, (err, address, family) => {
      if (err) return callback(err);
      const list = Array.isArray(address) ? address : [{ address, family }];
      const blocked = list.find((a) => isBlockedIp(a.address, strict));
      if (blocked) {
        const e = new Error(`Destination ${hostname} resolves to blocked address ${blocked.address}`);
        e.code = 'EBLOCKEDADDRESS';
        return callback(e);
      }
      callback(null, address, family);
    });
  };
}

module.exports = { checkUrl, guardedLookup, isBlockedIp, classifyIp };
