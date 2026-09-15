const https = require('https');
const { execSync } = require('child_process');

const cred = execSync('git credential fill', {
  input: 'protocol=https\nhost=github.com\n\n',
  encoding: 'utf8',
});
const token = (cred.match(/^password=(.*)$/m) || [])[1];

function get(url) {
  return new Promise((res, rej) => {
    const r = https.request(
      url,
      { method: 'GET', headers: { Authorization: 'Bearer ' + token, 'User-Agent': 'ci-check' } },
      (resp) => {
        let d = '';
        resp.on('data', (c) => (d += c));
        resp.on('end', () => res({ code: resp.statusCode, body: d }));
      }
    );
    r.on('error', (e) => res({ code: 0, body: 'ERR ' + e.message }));
    r.end();
  });
}

(async () => {
  const sha = execSync('git -C D:/桌面/xf rev-parse HEAD').toString().trim();
  console.log('main @', sha.slice(0, 7), '(public repo)');
  const r = await get(
    'https://api.github.com/repos/qmzzzzz/fsms/actions/runs?head_sha=' + sha + '&per_page=10'
  );
  const j = JSON.parse(r.body);
  if (!j.workflow_runs || j.workflow_runs.length === 0) {
    console.log('（尚未触发任何 run）');
    return;
  }
  for (const run of j.workflow_runs) {
    console.log(run.name + ' | ' + run.status + ' | ' + (run.conclusion || '-'));
    if (run.status === 'completed') {
      const jr = await get(
        'https://api.github.com/repos/qmzzzzz/fsms/actions/runs/' + run.id + '/jobs'
      );
      const jj = JSON.parse(jr.body);
      for (const job of jj.jobs || []) {
        if (job.conclusion !== 'success') {
          console.log('  ⚠ ' + job.name + ' | ' + (job.conclusion || job.status));
        }
      }
      const nonSuccess = (jj.jobs || []).filter(
        (x) => x.conclusion !== 'success' && x.conclusion !== 'skipped'
      ).length;
      if (nonSuccess === 0) console.log('  ✅ 全部 job 通过（含 skipped）');
    }
  }
})();
