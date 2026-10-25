/**
 * 审计 WAL 载体的权限收紧：目录 0700 / 文件 0600，跨平台实际执行并回读校验。
 *
 * 为什么不只在写文件时传 mode：POSIX 的 mode 只在**创建**时生效（已存在的文件保持原样），
 * Windows 更直接忽略它——WAL 里是尚未落库的审计取证，同机其他账户可读/可写等于
 * 审计完整性对本地用户开放。故启动时对目录与已知 WAL 文件（主文件 / 毒批归档 /
 * 原子替换残留）显式收紧，并在收紧后**回读**验证；写入路径再以 0600 创建新文件。
 *
 * 失败不阻断 WAL（best-effort，与 WAL 既有语义一致），但必须 error 级留痕并计入
 * 安全告警：权限是否真的收紧，不能靠“调用过 chmod/icacls”自证。
 */

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const filePermission = require('../utils/filePermission');
const { errText } = require('../utils/auditWriteFailure');

/**
 * 确保 WAL 目录存在且**确实可写**。
 *
 * 原实现只吞掉 mkdir 错误，startup() 仍无条件 walEnabled=true：目录不可写时
 * `isWalEnabled()` 对合规面板说谎，敏感操作 outbox 也会以为有可靠介质。
 * 这里返回布尔值，由 startup() 决定是否启用；失败必须 error 级留痕。
 *
 * @param {string} walPath
 * @returns {boolean}
 */
function ensureWalDirWritable(walPath) {
  const dir = path.dirname(walPath);
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (e) {
    logger.error(`审计 WAL 目录创建失败（${dir}）：${errText(e)}——WAL 未启用`);
    return false;
  }
  try {
    fs.accessSync(dir, fs.constants.W_OK);
    if (fs.existsSync(walPath)) fs.accessSync(walPath, fs.constants.W_OK);
  } catch (e) {
    logger.error(`审计 WAL 目录/文件不可写（${walPath}）：${errText(e)}——WAL 未启用`);
    return false;
  }
  return true;
}

function hardenTarget(target, isDir, recursive = true) {
  if (!fs.existsSync(target)) return;
  const result = filePermission.hardenPath(target, {
    isDir,
    recursive,
    log: (m) => logger.warn(m.replace(/^\u26a0\ufe0f?\s*/, '')),
  });
  const check = filePermission.verifyHardened(target);
  if (result.ok && check.tightened) return;

  logger.error(
    `审计 WAL ${isDir ? '目录' : '文件'}权限未能收紧（${target}）：` +
      `${result.detail || '未执行收紧'}；回读：${check.evidence}——` +
      '同机其他用户可能读取或改写尚未落库的审计取证，请立即核查'
  );
  try {
    require('../utils/metrics').incSecurityAlert('audit_wal_permission_not_tightened', 'high');
  } catch {
    /* 指标端不可用不影响告警日志 */
  }
}

/**
 * 启动时收紧 WAL 目录及已存在的载体文件。
 * `.tmp` 是原子替换的中间文件，崩溃窗口里同样可能含完整审计行。
 */
function hardenWalArtifacts(walPath) {
  // 目录不递归：WAL 常与其它日志共享 logs/，逐文件收紧才是本模块的职责范围
  hardenTarget(path.dirname(walPath), true, false);
  for (const suffix of ['', '.discarded', '.tmp']) hardenTarget(walPath + suffix, false);
}

module.exports = { hardenWalArtifacts, hardenTarget, ensureWalDirWritable };
