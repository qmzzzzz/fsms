const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const SRC = 'D:/桌面/xf';
const DST = 'D:/桌面/fsms';
const git = (cmd, cwd) => execSync(cmd, { cwd, maxBuffer: 1e8 }).toString('utf8');

const TOP_SKIP = new Set([
  '.git', 'node_modules', 'logs', 'coverage', 'secrets', 'dist', 'build',
  'test-results', 'playwright-report', '.workbuddy', '.mimosa',
  '.design_library', '.nyc_output', '.env', '.admin-initial-password',
  '.merkle-snapshot.json',
]);
const WEB_SKIP = new Set(['node_modules', 'dist', 'dist-optimized', 'coverage', 'test-results']);

function copyDeep(s, d, skip) {
  const st = fs.statSync(s);
  if (st.isDirectory()) {
    fs.mkdirSync(d, { recursive: true });
    for (const n of fs.readdirSync(s)) {
      if (skip && skip.has(n)) continue;
      copyDeep(path.join(s, n), path.join(d, n), null);
    }
  } else {
    fs.copyFileSync(s, d);
  }
}

// 1. 清 tracked 文件
const tracked = git('git ls-files -z', DST).split('\0').filter(Boolean);
for (const f of tracked) {
  try { fs.unlinkSync(path.join(DST, f)); } catch (_) {}
}
log('removed tracked:', tracked.length);

// 2. 复制
copyDeep(SRC, DST, TOP_SKIP);
copyDeep(path.join(SRC, 'web-admin'), path.join(DST, 'web-admin'), WEB_SKIP);
log('copied');

// 3. 暂存 + 树一致性校验
git('git add -A', DST);
const fsFiles = git('git ls-files', DST).split('\n').filter(Boolean).sort();
const xfFiles = git('git ls-files', SRC).split('\n').filter(Boolean).sort();
const onlyFs = fsFiles.filter((x) => !xfFiles.includes(x));
const onlyXf = xfFiles.filter((x) => !fsFiles.includes(x));
if (onlyFs.length || onlyXf.length) {
  console.error('MISMATCH only-fsms:', onlyFs, 'only-xf:', onlyXf);
  process.exit(1);
}
log('tree identical:', fsFiles.length, 'files');
