/**
 * 基于文件的密钥注入（P3-48）
 *
 * 问题：docker-compose 此前把 JWT_SECRET / AES_SECRET_KEY / MONGODB_URI（内含
 * 数据库口令）等全部经 `environment:` 传入。容器环境变量并非机密载体：
 *   - `docker inspect <container>` 完整回显 Config.Env，任何能访问 docker
 *     socket 的用户（通常等价于宿主 root）可直接读取；
 *   - `docker compose config` 会把 .env 展开后打印到终端与 CI 日志；
 *   - 环境变量被子进程无条件继承，任何 npm 生命周期脚本、崩溃转储、
 *     APM/错误上报 SDK 的「环境快照」都可能把密钥带走；
 *   - `/proc/<pid>/environ` 对同 uid 进程可读。
 *
 * 解法：支持 Docker/Kubernetes 通用的 `<NAME>_FILE` 约定 —— 密钥以文件形式
 * 挂载（compose 的 `secrets:` 会挂到 /run/secrets/<name>，K8s 用 Secret 卷），
 * 应用启动期读文件并回填到 process.env，其余代码零改动。
 *
 * 为何仍回填 process.env 而不是改造所有读取点：
 * 密钥读取点分散在 config/index.js、config/validate.js、utils/encryption.js、
 * utils/auditChain.js、authController.js 等处，逐个改造面大且容易漏。
 * 回填到 process.env 保留了单一注入点，同时把「密钥出现在 docker inspect」
 * 这个最外层、最易被扫描到的暴露面消掉。残余风险（进程内存、/proc/environ）
 * 需要 KMS/HSM 才能进一步收敛，此处不作过度承诺。
 */

const fs = require('fs');

/** 支持文件注入的密钥变量名（值敏感、不应出现在 docker inspect 中） */
const FILE_BACKED_SECRETS = Object.freeze([
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
  'AES_SECRET_KEY',
  'HMAC_SECRET',
  'LOGIN_ECDH_PRIVATE_KEY',
  'MONGODB_URI',
  'REDIS_URL',
  'MONGO_ROOT_PASSWORD',
  'ADMIN_INITIAL_PASSWORD',
  'DOCS_PASSWORD',
  'LOG_SHIPPING_TOKEN',
  'SENTRY_DSN',
]);

/**
 * 从 `<NAME>_FILE` 指向的文件读取密钥并回填 process.env[NAME]
 *
 * 冲突处理：同时提供 NAME 与 NAME_FILE 时以文件为准并告警。
 * 「静默优先其中之一」在密钥轮换场景下极其危险——运维以为换了文件，
 * 实际仍在用旧的环境变量值，且没有任何线索。
 *
 * 读取失败一律抛错而非跳过：跳过会让服务带着空密钥启动，
 * 随后要么被 validateConfig 以另一个不相关的错误信息拦下（误导排查方向），
 * 要么在开发环境静默使用弱默认值。
 *
 * @returns {{loaded: string[], warnings: string[]}} 已注入的变量名与告警
 */
function hydrateSecretsFromFiles() {
  const loaded = [];
  const warnings = [];

  for (const name of FILE_BACKED_SECRETS) {
    const filePathVar = `${name}_FILE`;
    const filePath = process.env[filePathVar];
    if (!filePath || !String(filePath).trim()) continue;

    let value;
    try {
      value = fs.readFileSync(String(filePath).trim(), 'utf8');
    } catch (err) {
      throw new Error(
        `${filePathVar} 指向的密钥文件不可读（${filePath}）：${err.message}。` +
          '容器场景请确认已挂载对应 secret 且文件属主/权限允许应用用户读取'
      );
    }

    // 去掉尾部换行：`echo "secret" > file` 与多数密钥管理工具都会追加 \n，
    // 带着它做 HMAC/AES 密钥会得到与预期不同的密钥，且症状是「解密全部失败」
    value = value.replace(/[\r\n]+$/, '');

    if (value.length === 0) {
      throw new Error(`${filePathVar} 指向的密钥文件为空（${filePath}）`);
    }

    if (process.env[name] !== undefined && process.env[name] !== value) {
      warnings.push(
        `${name} 与 ${filePathVar} 同时配置且取值不同，已采用文件内容。` +
          '请移除环境变量形式的配置，避免密钥轮换时新旧值并存'
      );
    }

    process.env[name] = value;
    loaded.push(name);
  }

  return { loaded, warnings };
}

module.exports = { FILE_BACKED_SECRETS, hydrateSecretsFromFiles };
