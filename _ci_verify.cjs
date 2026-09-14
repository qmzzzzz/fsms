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
    r.on('error', rej);
    r.end();
  });
}

(async () => {
  const shas = { '9438338f': 'main@9438338', '6b448729': 'master@6b44872' };
  // 用完整 sha 查：先取本地完整 sha
  const full = {
    main: execSync('git -C D:/桌面/fsms rev-parse HEAD').toString().trim(),
    master: execSync('git -C D:/桌面/xf rev-parse HEAD').toString().trim(),
  };
  for (const [branch, sha] of Object.entries(full)) {
    const r = await get(
      'https://api.github.com/repos/qmzzzzz/fsms/actions/runs?head_sha=' + sha + '&per_page=20'
    );
    const j = JSON.parse(r.body);
    console.log('=== ' + branch + ' @ ' + sha.slice(0, 7) + ' ===');
    if (!j.workflow_runs || j.workflow_runs.length === 0) {
      console.log('  （尚未触发任何 run）');
      continue;
    }
    for (const run of j.workflow_runs) {
      console.log('  ' + run.name + ' | ' + run.status + ' | ' + (run.conclusion || '-'));
      if (run.name === 'CodeQL') {
        const jr = await get(
          'https://api.github.com/repos/qmzzzzz/fsms/actions/runs/' + run.id + '/jobs'
        );
        const jj = JSON.parse(jr.body);
        for (const job of jj.jobs || []) {
          console.log(
            '    └ job: ' + job.name + ' | ' + job.status + ' | ' + (job.conclusion || '-')
          );
        }
      }
    }
  }
})();
