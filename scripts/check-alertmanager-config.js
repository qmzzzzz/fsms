#!/usr/bin/env node
/**
 * 直接 Compose 启动的告警配置硬闸（S-5，2026-10-20）
 *
 * 缺陷形状：`scripts/deploy.js` 的发布前置会以生产口径校验 Alertmanager 配置，
 * 但绕过部署脚本的 `docker compose up -d` 直接挂载仓库内的占位模板——告警栈
 * 「健康」运行，critical 却全部发往 hooks.example.com，事故时无人被叫醒。
 *
 * 本脚本作为 compose 的一次性校验容器（alertmanager 以
 * `condition: service_completed_successfully` 依赖它）运行，判据与部署路径同源
 * （复用 scripts/compliance-alerting.js，不允许两套解析口径）。
 *
 * 退出码：0 = 放行；1 = 拒绝启动（占位/误配/读不到）。
 * 演练环境可用 ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true 显式豁免占位（会打印警告）；
 * 误配形态任何声明都不放行。
 */
'use strict';

const fs = require('fs');
const { evaluateAlertingDelivery } = require('./compliance-alerting');
const {
  resolveAlertmanagerConfigPath,
  CONTAINER_ALERTMANAGER_CONFIG_PATH,
} = require('./alertmanager-config-path');

// argv[2] 优先（compose 显式传挂载点），其次 ALERTMANAGER_CONFIG_PATH，
// 最后回退容器内挂载点。解析规则与部署预检/合规检查共用（A-6）。
const file =
  process.argv[2] || resolveAlertmanagerConfigPath(process.env, CONTAINER_ALERTMANAGER_CONFIG_PATH);
const allowPlaceholder =
  (process.env.ALLOW_PLACEHOLDER_ALERT_WEBHOOK || '').trim().toLowerCase() === 'true';

function main() {
  let source;
  try {
    source = fs.readFileSync(file, 'utf8');
  } catch (err) {
    console.error(
      `[alert-config-check] 拒绝启动：无法读取告警配置 ${file}（${err.code || err.message}）`
    );
    return 1;
  }

  const production = evaluateAlertingDelivery(source, 'production');
  if (production.passed) {
    console.log(`[alert-config-check] 通过：${production.detail}`);
    return 0;
  }

  // 仓库态同样为红 ⇒ 误配/断链，不是「模板占位」，不接受任何豁免声明
  if (!evaluateAlertingDelivery(source, 'repo').passed) {
    console.error(
      `[alert-config-check] 拒绝启动：${production.detail}（该形态在仓库态同样为红，不是模板占位）`
    );
    return 1;
  }

  if (allowPlaceholder) {
    console.warn(
      `[alert-config-check] 已显式允许占位告警通道：本次启动后告警不会触达任何人。${production.detail}`
    );
    return 0;
  }

  console.error(
    `[alert-config-check] 拒绝启动：${production.detail}。` +
      '生产请用 ALERTMANAGER_CONFIG_PATH 指向已注入真实通道的配置；' +
      '确为无告警的演练环境时，显式设置 ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true 后重试。'
  );
  return 1;
}

process.exit(main());
