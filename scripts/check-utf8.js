// 扫描 web-admin 源码中非 UTF-8 文件
const fs = require('fs');
const path = require('path');

const roots = [path.join(__dirname, '..', 'web-admin')];
const skip = new Set(['node_modules', 'dist', '.git']);

// 常见二进制扩展名：内容本就不是文本，UTF-8 校验必然误报，直接跳过
const binaryExts = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.ico',
  '.webp',
  '.bmp',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.otf',
  '.pdf',
  '.zip',
  '.gz',
  '.bz2',
  '.xz',
  '.7z',
  '.rar',
  '.mp3',
  '.mp4',
  '.webm',
  '.avi',
  '.mov',
  '.wav',
]);

function walk(dir, out) {
  for (const name of fs.readdirSync(dir)) {
    if (skip.has(name)) continue;
    const full = path.join(dir, name);
    const st = fs.statSync(full);
    if (st.isDirectory()) walk(full, out);
    else out.push(full);
  }
}

const files = [];
for (const r of roots) {
  // 目录不存在时跳过并提示，避免 readdirSync ENOENT 直接崩溃
  if (!fs.existsSync(r)) {
    console.warn(`[跳过] 目录不存在：${r}`);
    continue;
  }
  walk(r, files);
}

const bad = [];
for (const f of files) {
  if (binaryExts.has(path.extname(f).toLowerCase())) continue;
  const buf = fs.readFileSync(f);
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    bad.push(f);
  }
}

if (bad.length === 0) {
  console.log('ALL_FILES_ARE_UTF8');
  process.exit(0);
} else {
  console.log('NON_UTF8_FILES:');
  for (const f of bad) console.log(f);
  process.exit(1);
}
