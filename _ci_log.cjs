const https = require('https');
const { execSync } = require('child_process');

const cred = execSync('git credential fill', {
  input: 'protocol=https\nhost=github.com\n\n',
  encoding: 'utf8',
});
const token = (cred.match(/^password=(.*)$/m) || [])[1];

function get(url, withAuth = true) {
  return new Promise((res, rej) => {
    const headers = { 'User-Agent': 'ci-check' };
    if (withAuth) headers.Authorization = 'Bearer ' + token;
    const r = https.request(url, { method: 'GET', headers }, (resp) => {
      // 手动跟 302：第二跳按 skill 指引不带 Auth
      if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
        get(resp.headers.location, false).then(res, rej);
        return;
      }
      let d = '';
      resp.on('data', (c) => (d += c));
      resp.on('end', () => res({ code: resp.statusCode, body: d }));
    });
    r.on('error', rej);
    r.end();
  });
}

(async () => {
  const sha = execSync('git -C D:/桌面/fsms rev-parse HEAD').toString().trim();
  const r = await get(
    'https://api.github.com/repos/qmzzzzz/fsms/actions/runs?head_sha=' + sha + '&per_page=20'
  );
  const j = JSON.parse(r.body);
  let jobId = null;
  for (const run of j.workflow_runs || []) {
    if (run.name !== 'CI') continue;
    const jr = await get('https://api.github.com/repos/qmzzzzz/fsms/actions/runs/' + run.id + '/jobs');
    const jj = JSON.parse(jr.body);
    const job = (jj.jobs || []).find((x) => x.name === 'test (18.x)');
    if (job) jobId = job.id;
  }
  if (!jobId) {
    console.log('job test (18.x) not found');
    return;
  }
  console.log('job id:', jobId);
  const lr = await get('https://api.github.com/repos/qmzzzzz/fsms/actions/jobs/' + jobId + '/logs');
  const lines = lr.body.split(/\r?\n/);
  // 找失败标记与错误摘要
  const failIdx = [];
  lines.forEach((l, i) => {
    if (/✕|×|FAIL |Tests:|●/.test(l)) failIdx.push(i);
  });
  // 输出 Tests: 汇总行和若干失败上下文
  for (const i of failIdx) {
    const l = lines[i];
    if (/Tests:\s/.test(l)) console.log(l.trim().slice(0, 150));
  }
  console.log('--- 失败块（前 5 个 ● 摘要）---');
  let shown = 0;
  for (const i of failIdx) {
    if (!/●/.test(lines[i])) continue;
    if (shown++ >= 5) break;
    console.log(lines.slice(i, i + 12).join('\n').slice(0, 1200));
    console.log('····');
  }
  fs_save(lr.body);
})();

function fs_save(body) {
  require('fs').writeFileSync('D:/桌面/xf/_ci_log_18x.txt', body);
  console.log('full log saved: _ci_log_18x.txt (' + body.length + ' bytes)');
}
