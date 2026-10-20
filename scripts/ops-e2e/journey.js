'use strict';

const fs = require('fs');
const path = require('path');

const JOURNEY_MODULES = {
  'alert-delivery': './journeys/alert-delivery',
  'deploy-rollback': './journeys/deploy-rollback',
  'backup-restore': './journeys/backup-restore',
  'cross-department': './journeys/cross-department',
};

const id = process.argv[2];
const configPath = process.argv[3];

if (!JOURNEY_MODULES[id] || !configPath) {
  console.error('用法：node scripts/ops-e2e/journey.js <旅程> <config.json>');
  process.exit(2);
}

let config;
try {
  config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
} catch (err) {
  console.error(`[ops-e2e:${id}] 读不到配置 ${configPath}：${err.message}`);
  process.exit(2);
}

const journey = require(path.join(__dirname, JOURNEY_MODULES[id]));

journey
  .main(config)
  .then((ok) => {
    process.exit(ok ? 0 : 1);
  })
  .catch((err) => {
    console.error(`[ops-e2e:${id}] 异常：${err.stack || err.message}`);
    process.exit(1);
  });
