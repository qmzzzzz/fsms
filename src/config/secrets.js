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
  // Redis 认证口令（2026-10-01 审计 finding：compose 的 redis 无 --requirepass，
  // 与监控栈同处一张扁平网络）。与 REDIS_URL 同规格：不进 environment，
  // 经 <NAME>_FILE 从 /run/secrets 注入；建连点（sharedCache / websocketService）
  // 以 ioredis 的 password 选项携带，避开 URL userinfo 的 percent-encoding 约束。
  'REDIS_PASSWORD',
  'MONGO_ROOT_PASSWORD',
  'ADMIN_INITIAL_PASSWORD',
  'DOCS_PASSWORD',
  'LOG_SHIPPING_TOKEN',
  'SENTRY_DSN',
  // I-L2（改后审计）：运行期敏感值同样支持 *_FILE 注入
  'METRICS_TOKEN',
  'SECURITY_ALERT_WEBHOOK_SECRET',
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
    //
    // 前导 BOM 同理且更隐蔽：Windows 记事本编辑过的 secret 文件、带 BOM 的
    // ConfigMap/`file:` 挂载产物都以 EF BB BF 开头，而 Node 的 utf8 解码**不会**
    // 剥掉它。结果是服务带着错密钥"成功"启动：AES 侧所有 `enc:v1:` 数据 GCM 认证
    // 失败 ⇒ mfaSecret 解密返回空串 ⇒ base32Decode 抛 ⇒ 全部 MFA 用户报「验证码错误」，
    // 与用户输错码的表现完全一致，排查方向会被带偏到验证码上。
    value = value.replace(/^\uFEFF/, '').replace(/[\r\n]+$/, '');

    // NUL 一律拒绝，且必须判在**赋给 process.env 之前**：Node 的 utf8 解码会把 NUL
    // 原样留在 JS 字符串里（`trim()` 也不认它是空白，所以既不改值也不触发下面的
    // 空白告警），而把含 NUL 的串赋给环境变量时实测（Windows / Node 24.18）**不抛错**、
    // 按 C 字符串在第一个 NUL 处截断，回读 `'A\0b'` 得到 `'A'`。UTF-16"另存为"的密钥文件
    // ——每个 ASCII 字符后面都跟一个 00 —— 会让服务带着"只剩首字符"的密钥成功启动。
    // 能不能被下游拦住纯属巧合：JWT/REFRESH/AES/HMAC 有 ≥32 长度闸、DOCS_PASSWORD 有
    // ≥16 闸（这些会启动失败，吵得响），而 METRICS_TOKEN / SECURITY_ALERT_WEBHOOK_SECRET /
    // LOG_SHIPPING_TOKEN / MONGO_ROOT_PASSWORD / SENTRY_DSN / REDIS_URL 没有长度判据，
    // 它们的失败形态是"进程活着但对不上"——webhook 签名校验失败等于安全告警静默丢弃。
    // 判据因此放在唯一的注入入口，而不是散到 16 个下游校验里。
    //
    // 只拒 NUL，不拒"所有控制字符"：LOGIN_ECDH_PRIVATE_KEY 是多行 PEM，
    // 中间的 \n 完全合法，一刀切会把正常部署拦死。
    if (value.includes('\u0000')) {
      throw new Error(
        `${filePathVar} 指向的密钥文件含 NUL 字符（${filePath}）。` +
          '赋给环境变量时会在第一个 NUL 处静默截断，注入的将不是文件里写的那串密钥；' +
          '多为 UTF-16/二进制"另存为"的产物，请用 UTF-8（无 BOM）重写该文件'
      );
    }

    // 首尾空白（BOM 之外的空格/Tab）保持原样不裁：真有密钥以空格为内容时静默裁掉
    // 会复现上面同一症状，所以这里只喊不改。
    if (value !== value.trim()) {
      warnings.push(
        `${filePathVar} 指向的密钥文件内容首尾含空白字符，已按原样保留：` +
          '若这不是有意为之，它会参与密钥派生并导致所有既有密文/MFA 种子解密失败'
      );
    }

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
