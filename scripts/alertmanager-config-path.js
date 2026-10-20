/**
 * Alertmanager 配置路径的单一解析口径（A-6）
 *
 * 三条读配置的路径此前各写各的：部署预检 deployPolicy 支持
 * ALERTMANAGER_CONFIG_PATH，合规检查 compliance-check 硬编码仓库模板，
 * compose 校验容器 check-alertmanager-config 自带 /etc 兜底。
 * 于是同一套判据（compliance-alerting）可能喂给不同的文件——合规检查对着
 * 仓库占位模板的下结论，而容器里实际挂载的是另一份配置（或反之）。
 *
 * 本模块只做路径决策：显式环境变量优先，空串/未设置才回退调用方给定的缺省值。
 * 缺省值仍由调用方决定（仓库模板 / 容器挂载点），但解析规则只此一份。
 */
'use strict';

const path = require('path');

const REPO_ALERTMANAGER_CONFIG_PATH = path.join(
  path.resolve(__dirname, '..'),
  'deployment',
  'observability',
  'alertmanager.yml'
);

/** compose 校验容器内 alertmanager 的挂载点 */
const CONTAINER_ALERTMANAGER_CONFIG_PATH = '/etc/alertmanager/alertmanager.yml';

/**
 * @param {Record<string,string|undefined>} [env] 环境变量
 * @param {string} [fallback] 未配置 ALERTMANAGER_CONFIG_PATH 时使用的路径
 * @returns {string}
 */
function resolveAlertmanagerConfigPath(
  env = process.env,
  fallback = REPO_ALERTMANAGER_CONFIG_PATH
) {
  const configured =
    env && typeof env.ALERTMANAGER_CONFIG_PATH === 'string'
      ? env.ALERTMANAGER_CONFIG_PATH.trim()
      : '';
  return configured || fallback;
}

/**
 * 按同一口径解析并读取配置。读不到（不存在 / EACCES / EISDIR）一律返回 null，
 * 与「读到空文件」区分开；是否放行由调用方的判据决定。
 *
 * @returns {{file: string, source: string|null}}
 */
function readAlertmanagerConfig(env = process.env, fsImpl = require('fs')) {
  const file = resolveAlertmanagerConfigPath(env);
  try {
    return {
      file,
      source: fsImpl.existsSync(file) ? String(fsImpl.readFileSync(file, 'utf8')) : null,
    };
  } catch (_) {
    return { file, source: null };
  }
}

module.exports = {
  resolveAlertmanagerConfigPath,
  readAlertmanagerConfig,
  REPO_ALERTMANAGER_CONFIG_PATH,
  CONTAINER_ALERTMANAGER_CONFIG_PATH,
};
