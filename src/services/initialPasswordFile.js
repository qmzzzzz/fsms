/**
 * 默认管理员初始口令文件（`.admin-initial-password`）的一次性生命周期。
 *
 * 该文件是明文凭据，存在的唯一理由是「首次登录时把随机生成的口令交给运维」。
 * 一旦默认管理员成功登录（口令已被使用）或完成改密（旧口令作废），它就必须消失；
 * 留在磁盘上等于给同机用户一份长期有效的管理员口令副本。
 *
 * 只有默认超管能触发删除：注册/普通用户登录也会走到同一钩子，不能误删。
 * 删除失败不阻断登录（认证成功不应因清理失败而回滚），但必须 error + 安全告警。
 */

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { getSuperAdminUsername } = require('../utils/superAdmin');

const FILE_NAME = '.admin-initial-password';

const filePath = () => path.join(process.cwd(), FILE_NAME);

const isDefaultAdmin = (username) =>
  typeof username === 'string' && username.toLowerCase() === getSuperAdminUsername().toLowerCase();

const alert = (type) => {
  try {
    require('../utils/metrics').incSecurityAlert(type, 'high');
  } catch {
    /* 指标端不可用不影响告警日志 */
  }
};

/**
 * 删除初始口令文件（一次性凭据语义）
 * @param {string} username 本次成功认证/改密的用户名
 * @param {string} trigger 人类可读的触发原因（日志用）
 * @returns {boolean} 是否确实删除了文件
 */
function consume(username, trigger) {
  if (!isDefaultAdmin(username)) return false;
  const target = filePath();
  if (!fs.existsSync(target)) return false;

  try {
    fs.unlinkSync(target);
    logger.info(`默认管理员已${trigger}，初始密码文件已删除：${target}`);
    return true;
  } catch (e) {
    logger.error(
      `初始密码文件删除失败（${target}）：${e.message}——该文件含明文初始口令，请立即手动删除`
    );
    alert('admin_initial_password_file_delete_failed');
    return false;
  }
}

module.exports = { consume, filePath, isDefaultAdmin };
