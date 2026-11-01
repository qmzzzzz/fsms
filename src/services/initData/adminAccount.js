/**
 * 系统初始化数据服务 · 默认管理员创建与超管归属对账（密码落盘）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

const crypto = require('crypto');
const Role = require('../../models/Role');
const User = require('../../models/User');
const logger = require('../../utils/logger');
const { SUPER_ADMIN_ROLE_CODE, getSuperAdminUsername } = require('../../utils/superAdmin');
const { validatePasswordStrength } = require('../../utils/helpers');
const { requiresProductionSemantics } = require('../../config/validate');
const initialPasswordFile = require('../initialPasswordFile');

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
 * fail-closed：写入或权限收紧任一失败 ⇒ 删除明文文件并返回 false，
 * 由调用方回滚管理员创建并中止启动。留下一个“权限未知”的明文口令文件，
 * 比暂时无法登录更危险——运维可用 ADMIN_INITIAL_PASSWORD 注入后重试。
 *
 * @param {string} adminPassword 已生成或来自环境变量的管理员口令
 * @returns {boolean} 口令是否已在安全载体中就绪（环境变量注入也算）
 */
function persistInitialPassword(adminPassword) {
  // 显式由环境变量注入时，不落盘（运维已知晓口令，落盘反而多一处泄露面）
  if (process.env.ADMIN_INITIAL_PASSWORD) {
    logger.warn('*** 请及时修改默认管理员密码！***');
    return true;
  }

  const fs = require('fs');
  const pwdFile = initialPasswordFile.filePath();
  try {
    fs.writeFileSync(
      pwdFile,
      `username: ${getSuperAdminUsername()}\npassword: ${adminPassword}\n`,
      { mode: 0o600 }
    );
  } catch (e) {
    // 修复：文件写入失败时绝不将密码明文输出到 stdout/日志
    // （容器环境 stdout 会被日志驱动持久化，等同密码泄露）。
    // 只提示可操作的恢复途径；密码仅存在于内存，进程退出即丢失。
    logger.error(
      `初始密码文件写入失败（${e.message}）。请设置 ADMIN_INITIAL_PASSWORD 环境变量后重启；` +
        '切勿从日志中查找密码（密码未被记录）。'
    );
    try {
      require('../../utils/metrics').incSecurityAlert(
        'admin_initial_password_write_failed',
        'high'
      );
    } catch {
      /* 指标端不可用不影响告警日志 */
    }
    return false;
  }

  const { hardenPath, verifyHardened } = require('../../utils/filePermission');
  const hardened = hardenPath(pwdFile, {
    // 去掉文件权限助手加的前缀符号（⚠️ + 空格），避免日志里出现双重告警标记
    log: (m) => logger.warn(m.replace(/^\u26a0\ufe0f?\s*/, '')),
  });
  const check = verifyHardened(pwdFile);

  if (hardened.ok && check.tightened) {
    logger.info(`管理员初始密码已写入 ${pwdFile}（已收紧权限并复核通过），请尽快登录后修改`);
    return true;
  }

  let removed = false;
  try {
    fs.unlinkSync(pwdFile);
    removed = true;
  } catch (e) {
    logger.error(`权限收紧失败后删除明文口令文件也失败（${pwdFile}）：${e.message}`);
  }
  logger.error(
    `管理员初始密码文件权限**未能收紧**（${hardened.detail || check.evidence}）：` +
      (removed
        ? '已删除该明文文件并回滚本次管理员创建。'
        : `${pwdFile} 仍含明文口令，请立即手动删除。`) +
      '请设置 ADMIN_INITIAL_PASSWORD 环境变量后重启'
  );
  try {
    require('../../utils/metrics').incSecurityAlert(
      'admin_initial_password_permission_not_tightened',
      'high'
    );
  } catch {
    /* 指标端不可用不影响告警日志 */
  }
  return false;
}

/** 初始口令无法安全保存时回滚刚创建的管理员（返回是否回滚成功） */
async function rollbackDefaultAdmin(admin) {
  try {
    await User.deleteOne({ _id: admin._id });
    logger.error(`默认管理员创建已回滚（_id=${admin._id}）：初始口令未能安全保存`);
    return true;
  } catch (e) {
    logger.error(
      `默认管理员回滚失败（${e.message}）：账户 ${admin._id} 仍存在但口令未知，请手动删除后重试`
    );
    return false;
  }
}

/** 生成满足口令策略的随机初始口令（128 位随机段 + 四类字符） */
const generateInitialAdminPassword = () => `Aa1!${crypto.randomBytes(14).toString('hex')}`;

/**
 * 解析默认管理员口令：显式注入值在生产语义下必须过与建号/改密相同的强度校验，
 * 未注入时生成满足策略的随机口令。
 */
const resolveInitialAdminPassword = () => {
  const explicitPassword = process.env.ADMIN_INITIAL_PASSWORD;
  if (!explicitPassword) return generateInitialAdminPassword();

  if (requiresProductionSemantics()) {
    const strengthError = validatePasswordStrength(explicitPassword);
    if (strengthError) {
      throw new Error(
        `ADMIN_INITIAL_PASSWORD 不满足口令强度要求：${strengthError}。` +
          '请改用至少 12 位、含大小写/数字/特殊字符且不在常见泄露口令表中的值后重启'
      );
    }
  }
  return explicitPassword;
};

/**
 * 并发首次启动时的同名账户复用。
 *
 * 「判重 → 创建」之间另一实例（或滚动部署的新 Pod）可能已经建好同名账户，
 * User.create 于是抛 username 唯一键冲突。这不是错误：复用赢家的账户即可。
 * 但**不得**继续 persistInitialPassword —— 本实例生成的口令与赢家账户的实际
 * 口令不同，写下去等于给运维一份永远登录不上的凭据，还会覆盖赢家已落盘的
 * 那份。返回 null 表示读不到赢家（不吞错，由调用方重新抛出原始错误）。
 */
async function findConcurrentAdminWinner(username) {
  const winner = await User.findByUsername(username);
  if (!winner) return null;
  logger.warn('并发首次启动：默认管理员已由另一实例创建，本实例复用该账户且不覆盖初始口令文件');
  return winner;
}

/**
 * 默认管理员创建的唯一键冲突处理。
 *
 * 两类冲突：
 *  - username：并发创建，复用赢家（createdHere=false，跳过硬编码口令落盘）；
 *  - emailKey/email：邮箱被外部注册抢注，降级到唯一后备邮箱后重建。
 *    两个键名都要认——`emailKey_1` 是新索引，`email_1` 是遗留明文索引，
 *    后者要等 reconcileUserIndexes 四步走完才被删掉。只认一个会把
 *    "邮箱被抢注"误判成未知错误 → 重新抛 → 开机 DoS。
 * @returns {Promise<{admin: object, createdHere: boolean}>}
 */
async function resolveAdminCreateConflict(err, { username, desiredEmail, createWith }) {
  const conflictKey = err?.code === 11000 ? Object.keys(err.keyPattern || {})[0] : null;

  if (conflictKey === 'username') {
    const winner = await findConcurrentAdminWinner(username);
    if (winner) return { admin: winner, createdHere: false };
    throw err;
  }

  if (conflictKey !== 'emailKey' && conflictKey !== 'email') throw err;

  const fallbackEmail = `admin+${Date.now().toString(36)}@localhost.invalid`;
  logger.warn(
    `默认管理员邮箱 ${desiredEmail} 已被占用（可能被外部注册抢占），` +
      `降级使用 ${fallbackEmail} 以避免启动失败；请登录后修改为真实邮箱`
  );
  try {
    return { admin: await createWith(fallbackEmail), createdHere: true };
  } catch (fallbackErr) {
    const winner =
      fallbackErr?.code === 11000 && Object.keys(fallbackErr.keyPattern || {})[0] === 'username'
        ? await findConcurrentAdminWinner(username)
        : null;
    if (winner) return { admin: winner, createdHere: false };
    throw fallbackErr;
  }
}

/**
 * 初始口令落盘 + 失败回滚。
 *
 * createdHere=false（复用了并发实例创建的账户）时必须直接返回：
 * 口令文件属于真正创建账户的那个实例，这里没有可落盘的口令。
 */
async function finalizeDefaultAdmin(admin, adminPassword, createdHere) {
  if (!createdHere) return admin;

  logger.info('默认管理员账户已创建', { username: getSuperAdminUsername() });
  if (!persistInitialPassword(adminPassword)) {
    const rolledBack = await rollbackDefaultAdmin(admin);
    throw new Error(
      '初始管理员口令未能安全保存（写入或权限收紧失败）。' +
        (rolledBack ? '本次管理员创建已回滚，' : '自动回滚失败，请手动删除默认管理员账户，') +
        '请设置 ADMIN_INITIAL_PASSWORD 环境变量后重启'
    );
  }
  return admin;
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

  // 显式注入值在生产语义下必须过硬性强度校验——否则 `password1234` 这类
  // 12 位弱口令会被直接播种成 SUPER_ADMIN，而等保证据却写着"初始口令强校验"。
  const adminPassword = resolveInitialAdminPassword();

  // 邮箱可配置：原先硬编码 'admin@example.com'，而 email 有唯一索引，
  // 且 createDefaultAdmin 只按 username 判重。若在公开注册开启期间有人抢注该邮箱，
  // 后续全新环境启动时 User.create 抛 E11000 → initializeSystem rethrow → 进程退出，
  // 形成可远程触发的开机 DoS。
  // 两层防护：① 允许用 ADMIN_INITIAL_EMAIL 覆盖；② 撞唯一键时自动降级为唯一后备邮箱。
  const desiredEmail = (process.env.ADMIN_INITIAL_EMAIL || '').trim() || 'admin@example.com';
  const username = getSuperAdminUsername();

  // bootstrap 超管同样置 mustChangePassword：它是全新部署里唯一持有最高权限的账户，
  // 初始口令（可能来自 ADMIN_INITIAL_PASSWORD 或落盘文件）在本人改密前只可用于改密。
  const createWith = (email) =>
    User.create({
      username,
      email,
      password: adminPassword,
      realName: '系统管理员',
      status: 'active',
      mustChangePassword: true,
      roles: [adminRole._id],
    });

  // 创建时一并写入 roles，单次落库：原先「create 后再 save 绑定角色」的两步写
  // 在两步之间进程中断会留下无角色的 admin 账户（登录后权限为空）
  let admin;
  let createdHere = true;
  try {
    admin = await createWith(desiredEmail);
  } catch (err) {
    ({ admin, createdHere } = await resolveAdminCreateConflict(err, {
      username,
      desiredEmail,
      createWith,
    }));
  }

  return finalizeDefaultAdmin(admin, adminPassword, createdHere);
};

/**
 * 超级管理员归属对账
 *
 * 唯一超管是系统不变量，且**只在此处**被写入——所有 HTTP 接口一律拒绝
 * 变更超管归属（见 utils/superAdmin.js 的设计说明）。因此这里是唯一的
 * 修复入口：无论归属如何丢失（误操作、直连数据库改动、迁移遗漏），
 * 重启一次即自愈。
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
