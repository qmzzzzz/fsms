# ADR-001：登录口令 ECDH 信封加密

- **状态**：已接受（2026-09-28 / 2026-10-10 两轮复核与加固：实现已演进，见「后果与局限」）
- **日期**：2026-08-29（追溯建档）
- **涉及**：`src/utils/loginCipher.js`、`src/controllers/authController.js`、`web-admin/src/utils/loginCipher.js`

## 背景

登录、注册、改密、关闭 MFA 等接口需要传输用户口令。即便生产环境有 TLS（见 ADR 关联与优化清单 M-2），仍希望口令不以明文形态出现在请求体中，以降低以下风险面：中间设备/反代日志误记请求体、抓包留档、以及 TLS 配置疏漏时的被动窃听。

## 决策

采用「一次性 ECDH + HKDF + AES-256-GCM」信封加密传输口令：

1. 后端生成 ECDH 密钥对，`GET /api/auth/login-public-key`（`src/routes/authRoutes.js` 的 `router.get('/login-public-key', …)`）下发 `{publicKey, keyId, curve, algorithm}`（`src/utils/loginCipher.js` 的 `getPublicKeyInfo()`；`publicKey` 为 **PEM** 文本，非 JWK）。
2. 前端对每次提交生成一次性 ECDH 密钥对（WebCrypto），与服务端公钥 `deriveBits` 协商，经 HKDF‑SHA‑256（`info='login-credential'`，16B 随机 salt）派生 AES‑256 密钥，AES‑GCM 加密载荷 `{p:口令, ts:时间戳, nonce:随机数}`，输出 base64 信封 `{v,x,y,salt,iv,c}`（`web-admin/src/utils/loginCipher.js` 的 `encryptPassword()`；2026-10-10 起 GCM 的 additionalData 绑定端点用途，见「后果与局限」）。
3. 后端 `decryptLoginCredential()` 重建公钥 → `crypto.diffieHellman()` → HKDF → AES‑GCM 解密（`src/utils/loginCipher.js`；内部拆为 `parseCredentialEnvelope()` / `decryptCredentialPayload()` / `parseCredentialPayload()` 三段）。
4. 防重放：`ts` 校验 ±5 分钟窗口；`nonce` 经 `sharedCache.setIfAbsent()` 原子占位去重（Redis 就绪时跨实例生效，未配置时回退进程内去重；TTL 5 分钟）；GCM 认证标签保证篡改即失败。
5. 降级：不支持 WebCrypto / 非 secure context 时，前端返回 null 走明文兼容轨；路由层仅在 HTTPS/localhost 下可开 `strict`。

生效端点（口令解密的消费方）：登录、注册、改密、关闭 MFA。实际调用点为 `src/services/authService.js`（登录 / 注册 / 改密）与 `src/controllers/userController.js`（重置口令）、`src/controllers/mfaController.js`（关闭 MFA 前校验当前口令），均经 `decryptLoginCredential()`；`src/controllers/authController.js` 只负责用 `getPublicKeyInfo()` 下发公钥，不做解密。

> **2026-09-28 复核注记**：原文此处写「`authController.js` 264/122/852/1369 附近」，该行号既已漂移（`authController.js` 现仅 662 行，1369 超出文件长度），调用方归属亦有误（解密不在 authController）。已按上述实测改为符号引用。

## 理由

- **体积与强度**：P‑256 提供 128‑bit 安全强度，公钥/密文体积比 RSA‑OAEP 小一个数量级，适合每次登录现算。
- **零依赖**：浏览器 WebCrypto 与 Node 原生 `crypto` 均原生支持，无需引入第三方加密库。
- **前向性**：每次提交一次性密钥对，单次会话泄露不殃及其它请求。

## 备选方案

- **仅依赖 TLS**：最简单，但口令会以明文进入请求体，日志/抓包面更大；作为唯一防线对配置疏漏无兜底。
- **RSA‑OAEP 直接加密口令**：实现更直观，但密钥/密文体积大，且缺少 GCM 的认证与等量随机性语义。
- **SRP/PAKE**：能防服务端泄露口令哈希后的离线爆破，但实现与依赖复杂度高，超出当前收益。

## 后果与局限

- **不能替代 TLS**：ECDH 公钥经普通 HTTP 下发，挡不住主动 MITM（攻击者可替换公钥）。本机制定位为纵深防御，生产必须叠加 TLS 终结（优化清单 M-2，P0）。
- **nonce 去重在进程内存**：多实例部署下各进程 Map 独立，防重放不完整，需随 Redis 迁移（优化清单 R-3）。
  > **2026-09-28 复核注记**：R-3 已落地。现为 `sharedCache.setIfAbsent()` 原子占位，Redis 就绪时「重放无论命中哪个实例都被拒绝」，未配置时回退进程内去重（`src/utils/loginCipher.js` 的 `decryptLoginCredential()`）。本条局限仅对未配 `REDIS_URL` 的部署成立。
- **降级轨存在**：明文兼容轨在严格模式下可关闭，属可控取舍。
- **无前向保密（2026-10-10 复核）**：信封自带一次性临时公钥坐标，持有静态私钥（`LOGIN_ECDH_PRIVATE_KEY(_FILE)` 注入）即可对**任一历史密文**重新协商出共享密钥——静态私钥一旦泄露，此前捕获的全部登录信封可被追溯解密（登录口令多为复用口令，价值等同口令库泄露）。两种密钥模式取舍相反：静态私钥换取「重启后历史密文仍可解密」（利于取证/排障），临时密钥对模式（未注入私钥）则「私钥不出进程、历史密文攻不破，但重启即换钥、重启前密文永久不可解密」。泄露按口令泄露处置（轮换私钥 + 强制全体改密），预案见 `SECURITY.md`「登录口令加密的密钥管理」；轮换与前端钉扎的联动见 `deployment/secret-rotation.md`。
- **公钥下发无内建认证（2026-10-10 复核并收口）**：客户端每次从同一信道拉服务端公钥，不固定、不验签——主动中间人把公钥替换成自己的即可解密再转发，「截获密文无法恢复口令」只对**被动**窃听成立（对 HTTP 内网等无 TLS 形态，主动攻击下本机制形同虚设）。收口：构建期把公钥 SHA‑256 指纹钉进前端包（`VITE_LOGIN_PUBLIC_KEY_SHA256`，≥16 位十六进制前缀），`web-admin/src/utils/loginCipher.js` 的 `ensurePublicKey` 对**取到的 PEM** 自行计算指纹并比对，不符即抛 `PUBLIC_KEY_PIN_MISMATCH` 且不得降级明文。属纵深加固，不替代 TLS（见上条）。
- **信封不绑定用途（已修复，2026-10-10）**：原载荷只有 `{p, ts, nonce}`，未把端点用途纳入 GCM 的 additionalData——一条**从未到达服务端**的捕获信封（用户填完表单但提交失败/被丢弃，密文已上线）可在 ±5 分钟窗口内提交到任何接收密文口令的端点（nonce 去重只挡「已提交过」的信标）。现以 `CREDENTIAL_AAD` 绑定端点用途（login / register / password:current / password:new / mfa:disable / user:create），跨端点信封解密失败（fail-closed）。**刻意不把用户名绑进 AAD**：跨用户重放会在口令比对处自然失败（401），绑用户名零安全收益，却让前端每个表单多一个必须逐字一致的条件。
- **登录 ENC_INVALID 对客合并（2026-10-10）**：解密失败原映射 400 `AUTH_ENCRYPTED_CREDENTIAL_INVALID`，与 `AUTH_INVALID_CREDENTIALS` 可区分，可作弱预言机（判断某 nonce 是否已消费、信封是否在时间窗内）——与密文层「不回传客户端做区分」的设计意图矛盾。现登录端点统一映射 401 `AUTH_INVALID_CREDENTIALS`。register / changePassword / mfaDisable / userCreate **保留**独立错误码：这些端点输入由攻击者自控（注册新用户、改自己口令），无预言机价值，且前端的公钥缓存自愈（失效重取）依赖该码触发——自愈判定改由 `web-admin/src/utils/api.js` 按端点承担。

## 关联

- 优化清单：M-2（TLS 纵深）、R-3（nonce 迁 Redis，**已落地**）
- 测试：`src/tests/utils/loginCipher.test.js`、`src/tests/controllers/loginEncryption.test.js`、`web-admin/src/tests/utils/loginCipher.test.js`

> 注：本文出现的「优化清单 X-N」为建仓前遗留的历史编号（源文件 `deliverables/待优化项总清单-2026-08-29.md` 从未进入版本库且已不存在），无源可查。该编号体系已废弃，新提交一律使用 `P*/R*/T*`——详见 `CONTRIBUTING.md` §5。
