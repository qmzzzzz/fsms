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
      if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
        get(resp.headers.location, false).then(res, rej);
        return;
      }
      let d = '';
      resp.on('data', (c) => (d += c));
      resp.on('end', () => res({ code: resp.statusCode, body: d }));
    });
    r.on('error', (e) => res({ code: 0, body: 'ERR ' + e.message }));
    r.end();
  });
}

(async () => {
  const sha = execSync('git -C D:/桌面/fsms rev-parse HEAD').toString().trim();
  const r1 = await get(
    'https://api.github.com/repos/qmzzzzz/fsms/actions/runs?head_sha=' + sha + '&per_page=5'
  );
  const j = JSON.parse(r1.body);
  const run = (j.workflow_runs || []).find((x) => x.name === 'CI');
  console.log('run:', run.id, run.conclusion, '| run_attempt:', run.run_attempt);
  const jj = JSON.parse(
    (await get('https://api.github.com/repos/qmzzzzz/fsms/actions/runs/' + run.id + '/jobs')).body
  );
  for (const job of jj.jobs || []) {
    console.log('\n===== ' + job.name + ' (' + job.conclusion + ') =====');
    for (const s of job.steps || []) {
      if (s.conclusion !== 'success' && s.conclusion !== 'skipped') {
        console.log('  FAILED STEP:', s.name, '(' + s.conclusion + ')');
      }
    }
    if (job.conclusion === 'failure') {
      const lr = await get(
        'https://api.github.com/repos/qmzzzzz/fsms/actions/jobs/' + job.id + '/logs'
      );
      const lines = lr.body.split(/\r?\n/);
      const errs = lines.filter((l) => /##\[error\]|npm error|ECONN|ENOTFOUND|ETIMEDOUT|exit code|ELIFECYCLE/i.test(l));
      console.log('  log lines:', lines.length, '| error lines:', errs.length);
      for (const e of errs.slice(0, 6)) console.log('   >', e.trim().slice(0, 200));
    }
  }
})();
