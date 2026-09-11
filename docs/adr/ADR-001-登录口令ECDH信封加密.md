# ADR-001：登录口令 ECDH 信封加密

- **状态**：已接受
- **日期**：2026-08-29（追溯建档）
- **涉及**：`src/utils/loginCipher.js`、`src/controllers/authController.js`、`web-admin/src/utils/loginCipher.js`

## 背景

登录、注册、改密、关闭 MFA 等接口需要传输用户口令。即便生产环境有 TLS（见 ADR 关联与优化清单 M-2），仍希望口令不以明文形态出现在请求体中，以降低以下风险面：中间设备/反代日志误记请求体、抓包留档、以及 TLS 配置疏漏时的被动窃听。

## 决策

采用「一次性 ECDH + HKDF + AES-256-GCM」信封加密传输口令：

1. 后端生成 ECDH 密钥对，`GET /api/auth/login-public-key` 下发 `{publicKey(JWK), keyId, curve, algorithm}`（`src/routes/authRoutes.js:226` → `src/utils/loginCipher.js:108`）。
2. 前端对每次提交生成一次性 ECDH 密钥对（WebCrypto），与服务端公钥 `deriveBits` 协商，经 HKDF‑SHA‑256（`info='login-credential'`，16B 随机 salt）派生 AES‑256 密钥，AES‑GCM 加密载荷 `{p:口令, ts:时间戳, nonce:随机数}`，输出 base64 信封 `{v,x,y,salt,iv,c}`（`web-admin/src/utils/loginCipher.js:68`）。
3. 后端 `decryptLoginCredential()` 重建公钥 → `crypto.diffieHellman()` → HKDF → AES‑GCM 解密（`src/utils/loginCipher.js:134`）。
4. 防重放：`ts` 校验 ±5 分钟窗口；`nonce` 在进程内 Map 去重（TTL 5 分钟、上限 10000 条）；GCM 认证标签保证篡改即失败。
5. 降级：不支持 WebCrypto / 非 secure context 时，前端返回 null 走明文兼容轨；路由层仅在 HTTPS/localhost 下可开 `strict`。

生效端点：登录、注册、改密、关闭 MFA（`authController.js` 264/122/852/1369 附近）。

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
- **降级轨存在**：明文兼容轨在严格模式下可关闭，属可控取舍。

## 关联

- 优化清单：M-2（TLS 纵深）、R-3（nonce 迁 Redis）
- 测试：`src/tests/utils/loginCipher.test.js`、`src/tests/controllers/loginEncryption.test.js`、`web-admin/src/tests/utils/loginCipher.test.js`
