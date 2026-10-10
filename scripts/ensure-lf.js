const fs = require('fs');
const path = require('path');

function normalizeDirectory(dir) {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir);
  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      normalizeDirectory(fullPath);
    } else if (/\.(js|sh|json|md|html)$/.test(entry)) {
      const content = fs.readFileSync(fullPath, 'utf8');
      if (content.includes('\r')) {
        fs.writeFileSync(fullPath, content.replace(/\r\n/g, '\n'), 'utf8');
        console.log(`[prepack] Converted CRLF -> LF: ${path.relative(process.cwd(), fullPath)}`);
      }
    }
  }
}

const targets = ['bin', 'src', 'test'];
for (const target of targets) {
  normalizeDirectory(path.join(__dirname, '..', target));
}

// Check root files
const rootFiles = ['README.md', 'index.js', 'package.json', 'Dockerfile', 'SECURITY.md'];
for (const f of rootFiles) {
  const p = path.join(__dirname, '..', f);
  if (fs.existsSync(p)) {
    const c = fs.readFileSync(p, 'utf8');
    if (c.includes('\r')) {
      fs.writeFileSync(p, c.replace(/\r\n/g, '\n'), 'utf8');
      console.log(`[prepack] Converted CRLF -> LF: ${f}`);
    }
  }
}
console.log('✔ All files verified LF-clean.');
