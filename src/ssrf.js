const net = require('net');
const dns = require('dns');

function normalizeHost(host) {
  if (!host) return '';
  let h = host.toLowerCase().trim();
  if (h.startsWith('[') && h.endsWith(']')) {
    h = h.slice(1, -1);
  }
  return h;
}

function parseIpv4Int(hostname) {
  if (/^\d+$/.test(hostname)) {
    const num = parseInt(hostname, 10);
    if (num >= 0 && num <= 0xFFFFFFFF) {
      const b1 = (num >>> 24) & 255;
      const b2 = (num >>> 16) & 255;
      const b3 = (num >>> 8) & 255;
      const b4 = num & 255;
      return `${b1}.${b2}.${b3}.${b4}`;
    }
  }
  return null;
}

function isPrivateIp(ip) {
  if (!ip) return false;
  let normalized = normalizeHost(ip);

  const fromInt = parseIpv4Int(normalized);
  if (fromInt) {
    normalized = fromInt;
  }

  // IPv4-mapped IPv6: ::ffff:127.0.0.1 or ::ffff:7f00:1
  if (normalized.startsWith('::ffff:')) {
    const rest = normalized.slice(7);
    if (net.isIPv4(rest)) {
      normalized = rest;
    } else {
      const hexParts = rest.split(':');
      if (hexParts.length === 2) {
        const p1 = parseInt(hexParts[0], 16) || 0;
        const p2 = parseInt(hexParts[1], 16) || 0;
        const b0 = (p1 >>> 8) & 255;
        const b1 = p1 & 255;
        const b2 = (p2 >>> 8) & 255;
        const b3 = p2 & 255;
        normalized = `${b0}.${b1}.${b2}.${b3}`;
      }
    }
  }

  // IPv4 checks
  if (net.isIPv4(normalized)) {
    const parts = normalized.split('.').map(p => parseInt(p, 10));
    const [b0, b1] = parts;
    // 0.0.0.0/8
    if (b0 === 0) return true;
    // 127.0.0.0/8 (Loopback)
    if (b0 === 127) return true;
    // 10.0.0.0/8 (Private)
    if (b0 === 10) return true;
    // 172.16.0.0/12 (Private)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (b0 === 192 && b1 === 168) return true;
    // 169.254.0.0/16 (Link-local / Cloud metadata)
    if (b0 === 169 && b1 === 254) return true;
    // 100.64.0.0/10 (Carrier-Grade NAT: 100.64.0.0 to 100.127.255.255)
    if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;
    // 100.100.100.200 (Alibaba Cloud metadata)
    if (normalized === '100.100.100.200') return true;
    return false;
  }

  // IPv6 checks
  if (net.isIPv6(normalized)) {
    const lower = normalized.toLowerCase();
    // Loopback ::1
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
    // Unspecified ::
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;
    // Unique Local fc00::/7 (fc00:: to fdff::)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    // Link-local fe80::/10 (fe80:: to febf::)
    if (
      lower.startsWith('fe8') ||
      lower.startsWith('fe9') ||
      lower.startsWith('fea') ||
      lower.startsWith('feb')
    ) {
      return true;
    }
    return false;
  }

  return false;
}

function isPrivateOrMetadataUrl(urlString, strictSSRF = false) {
  try {
    const parsed = new URL(urlString);
    const rawHostname = parsed.hostname;
    const hostname = normalizeHost(rawHostname);

    // Always block cloud metadata domains and IPs
    if (
      hostname === '169.254.169.254' ||
      hostname === 'metadata.google.internal' ||
      hostname === '100.100.100.200' ||
      hostname.startsWith('169.254.')
    ) {
      return true;
    }

    const fromInt = parseIpv4Int(hostname);
    if (fromInt && (isPrivateIp(fromInt) || fromInt.startsWith('169.254.'))) {
      return true;
    }

    if (strictSSRF) {
      if (
        hostname === 'localhost' ||
        hostname.endsWith('.localhost') ||
        hostname.endsWith('.internal') ||
        hostname.endsWith('.local')
      ) {
        return true;
      }
      if (isPrivateIp(hostname)) {
        return true;
      }
    }
    return false;
  } catch (e) {
    return true;
  }
}

function guardedLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err, address, family);
    if (isPrivateIp(address)) {
      const blockErr = new Error(`SSRF blocked: ${hostname} resolved to private/loopback IP ${address}`);
      blockErr.code = 'ENOTFOUND';
      return callback(blockErr);
    }
    callback(null, address, family);
  });
}

module.exports = {
  isPrivateIp,
  isPrivateOrMetadataUrl,
  guardedLookup,
  normalizeHost
};
