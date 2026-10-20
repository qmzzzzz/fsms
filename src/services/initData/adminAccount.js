/**
 * 系统初始化数据服务 · 默认管理员创建与超管归属对账（密码落盘）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

const crypto = require('crypto');
const Role = require('../../models/Role');
const User = require('../../models/User');
const logger = require('../../utils/logger');
const { SUPER_ADMIN_ROLE_CODE, getSuperAdminUsername } = require('../../utils/superAdmin');

/**
 * 落盘初始密码并**确保权限已实际收紧**
 *
 * 两条安全约束同时在此满足：
 *   - 密码绝不写入日志（容器 stdout 会被日志驱动持久化），只落盘到文件。
 *   - 落盘后必须真正收紧权限。NTFS 不支持 POSIX 权限位，writeFileSync 的
 *     mode 参数在 Windows 上被忽略、chmodSync 也只能切换只读属性——此前「chmod 后
 *     忽略失败 + 日志照打权限 600」是最具误导性的失败形态：用户以为受保护，实际裸奔。
 *     现改用跨平台 utils/filePermission（Windows 走 icacls 切断继承）并**回读校验**，
 *     校验不过则明确告警该文件对本机其他用户可读。
 *
 * 抽成独立函数而非内联：createDefaultAdmin 已接近复杂度阈值，
 * 内联这段会让它超标（lint:ratchet 实测 0 → 1）。
 *
 * @param {string} adminPassword 已生成或来自环境变量的管理员口令
 */
function persistInitialPassword(adminPassword) {
  // 显式由环境变量注入时，不落盘（运维已知晓口令，落盘反而多一处泄露面）
  if (process.env.ADMIN_INITIAL_PASSWORD) {
    logger.warn('*** 请及时修改默认管理员密码！***');
    return;
  }

  try {
    const fs = require('fs');
    const path = require('path');
    const pwdFile = path.join(process.cwd(), '.admin-initial-password');
    fs.writeFileSync(
      pwdFile,
      `username: ${getSuperAdminUsername()}\npassword: ${adminPassword}\n`,
      { mode: 0o600 }
    );

    const { hardenPath, verifyHardened } = require('../../utils/filePermission');
    const hardened = hardenPath(pwdFile, {
      // 去掉文件权限助手加的前缀符号（⚠️ + 空格），避免日志里出现双重告警标记
      log: (m) => logger.warn(m.replace(/^\u26a0\ufe0f?\s*/, '')),
    });
    const check = verifyHardened(pwdFile);

    if (hardened.ok && check.tightened) {
      logger.info(`管理员初始密码已写入 ${pwdFile}（已收紧权限并复核通过），请尽快登录后修改`);
    } else {
      logger.warn(
        `管理员初始密码文件权限**未能收紧**（${hardened.detail || check.evidence}）：` +
          `${pwdFile} 可能对本机其他用户可读，请立即手动收紧或改用 ADMIN_INITIAL_PASSWORD 注入`
      );
      logger.info(`管理员初始密码已写入 ${pwdFile}，请尽快登录后修改`);
    }
  } catch (e) {
    // 修复：文件写入失败时绝不将密码明文输出到 stdout/日志
    // （容器环境 stdout 会被日志驱动持久化，等同密码泄露）。
    // 只提示可操作的恢复途径；密码仅存在于内存，进程退出即丢失，
    // 此时应通过 ADMIN_INITIAL_PASSWORD 显式指定后重启。
    logger.error(
      `初始密码文件写入失败（${e.message}）。请停止服务，通过环境变量 ADMIN_INITIAL_PASSWORD ` +
        '显式指定管理员初始密码后重新启动；切勿从日志中查找密码（密码未被记录）。'
    );
  }
}

/**
 * 创建默认管理员账户
 */
const createDefaultAdmin = async () => {
  logger.info('检查默认管理员账户...');

  const adminRole = await Role.findOne({ code: SUPER_ADMIN_ROLE_CODE });
  if (!adminRole) {
    logger.warn('未找到超级管理员角色，跳过管理员创建');
    return null;
  }

  const existingAdmin = await User.findByUsername(getSuperAdminUsername());
  if (existingAdmin) {
    logger.info('默认管理员账户已存在');
    return existingAdmin;
  }

  // 默认管理员密码：优先从环境变量读取，未配置时生成随机强密码
  const adminPassword =
    process.env.ADMIN_INITIAL_PASSWORD || crypto.randomBytes(16).toString('hex');

  // 邮箱可配置：原先硬编码 'admin@example.com'，而 email 有唯一索引，
  // 且 createDefaultAdmin 只按 username 判重。若在公开注册开启期间有人抢注该邮箱，
  // 后续全新环境启动时 User.create 抛 E11000 → initializeSystem rethrow → 进程退出，
  // 形成可远程触发的开机 DoS。
  // 两层防护：① 允许用 ADMIN_INITIAL_EMAIL 覆盖；② 撞唯一键时自动降级为唯一后备邮箱。
  const desiredEmail = (process.env.ADMIN_INITIAL_EMAIL || '').trim() || 'admin@example.com';
  const username = getSuperAdminUsername();

  /** 用指定邮箱创建管理员 */
  const createWith = (email) =>
    User.create({
      username,
      email,
      password: adminPassword,
      realName: '系统管理员',
      status: 'active',
      roles: [adminRole._id],
    });

  // 创建时一并写入 roles，单次落库：原先「create 后再 save 绑定角色」的两步写
  // 在两步之间进程中断会留下无角色的 admin 账户（登录后权限为空）
  let admin;
  try {
    admin = await createWith(desiredEmail);
  } catch (err) {
    // 仅对**邮箱唯一键**冲突降级；其他错误（含 username 冲突）照常抛出。
    // A3：冲突键名有两个可能的来源，必须都认——
    //   · `emailKey_1`：新索引（schema 上 email 的唯一约束已搬到检索键列）；
    //   · `email_1`：**遗留**索引（明文列），它要等 reconcileUserIndexes 四步走完
    //     才被删掉，在此之前仍会先于新索引报冲突。
    // 只认其中一个的后果是把"邮箱被抢注"误判成未知错误 → 重新抛 → 开机 DoS，
    // 而那正是本段两层防护要挡的东西。
    const conflictKey = err?.code === 11000 ? Object.keys(err.keyPattern || {})[0] : null;
    if (conflictKey !== 'emailKey' && conflictKey !== 'email') throw err;

    const fallbackEmail = `admin+${Date.now().toString(36)}@localhost.invalid`;
    logger.warn(
      `默认管理员邮箱 ${desiredEmail} 已被占用（可能被外部注册抢占），` +
        `降级使用 ${fallbackEmail} 以避免启动失败；请登录后修改为真实邮箱`
    );
    admin = await createWith(fallbackEmail);
  }

  logger.info('默认管理员账户已创建', { username: getSuperAdminUsername() });
  persistInitialPassword(adminPassword);

  return admin;
};

/**
 * 超级管理员归属对账
 *
 * 唯一超管是系统不变量，且**只在此处**被写入——所有 HTTP 接口一律拒绝
 * 变更超管归属（见 utils/superAdmin.js 的设计说明）。因此这里是唯一的
 * 修复入口：无论归属如何丢失（误操作、直连数据库改动、迁移遗漏），
 * 重启一次即自愈。
 *
 * 三类情形：
 * 1. 指定账户缺少超管角色 → 补回（覆盖「0 持有者」的不可恢复状态）
 * 2. 其他账户多持有超管角色 → 剥离并记 error 日志（唯一性收敛）
 * 3. 指定账户不存在 → 只告警不创建：账户创建有独立流程
 *    （createDefaultAdmin），此处凭空造号会绕开密码策略与审计
 *
 * @returns {Promise<void>}
 */
const reconcileSuperAdmin = async () => {
  const username = getSuperAdminUsername();
  logger.info('超级管理员归属对账', { username });

  const superRole = await Role.findOne({ code: SUPER_ADMIN_ROLE_CODE });
  if (!superRole) {
    logger.error('未找到 SUPER_ADMIN 角色，超管对账跳过（initRoles 应已播种该角色）');
    return;
  }
  if (!superRole.isBuiltIn) {
    // isBuiltIn 是所有超管保护判断的前置条件（isSuperAdminRole 要求二者同时成立），
    // 一旦为 false，全部 SUPER_ADMIN 保护逻辑静默失效
    logger.warn('SUPER_ADMIN 角色的 isBuiltIn 为 false，已强制修正为 true');
    await Role.updateOne({ _id: superRole._id }, { $set: { isBuiltIn: true } });
  }

  const target = await User.findByUsername(username);
  if (!target) {
    logger.warn(
      `超管目标账户 ${username} 不存在，归属对账跳过。` +
        '如需指定其他账户，请设置环境变量 SUPER_ADMIN_USERNAME'
    );
    return;
  }

  // 1) 目标账户补齐超管角色（$addToSet 幂等，不会重复push）
  // roles 为 null 的形态必须用 $set 修复：schema 默认值是 []，但绕过 schema 的写入
  // （直连数据库、迁移脚本、collection.insertOne）可留下 null，此时 $addToSet 会抛
  // MongoServerError（Cannot apply $addToSet to non-array field）。本函数是启动期
  // 唯一的超管自愈入口，抛错会让 initializeSystem 整体失败 → 进程退出，
  // 即「账户字段被污染」升级成「服务无法启动」（2026-09-18 实测复现）。
  const rolesIsArray = Array.isArray(target.roles);
  const targetHas = (target.roles || []).some((r) => String(r) === String(superRole._id));
  if (!targetHas) {
    await User.updateOne(
      { _id: target._id },
      rolesIsArray ? { $addToSet: { roles: superRole._id } } : { $set: { roles: [superRole._id] } }
    );
    logger.warn('已为账户补回 SUPER_ADMIN 角色（此前缺失，最高权限不可用）', { username });
    // 角色变化必须失效认证缓存，否则该账户已签发的会话仍按旧角色鉴权
    try {
      const { invalidateUserCache } = require('../../middleware/auth');
      invalidateUserCache(target._id);
    } catch (e) {
      logger.debug(`超管对账缓存失效跳过：${e.message}`);
    }
  }

  // 2) 其他账户剥离超管角色（唯一性收敛）
  const extras = await User.find({
    _id: { $ne: target._id },
    roles: superRole._id,
  }).select('username');

  if (extras.length > 0) {
    await User.updateMany(
      { _id: { $ne: target._id }, roles: superRole._id },
      { $pull: { roles: superRole._id } }
    );
    logger.error(
      `检测到 ${extras.length} 个非授权账户持有 SUPER_ADMIN 角色，已剥离：` +
        extras.map((u) => u.username).join('、')
    );
    try {
      const { invalidateUserCache } = require('../../middleware/auth');
      extras.forEach((u) => invalidateUserCache(u._id));
    } catch (e) {
      logger.debug(`超管对账缓存失效跳过：${e.message}`);
    }
  }

  logger.info('超级管理员归属已对齐', { username });
};

module.exports = { createDefaultAdmin, reconcileSuperAdmin };
