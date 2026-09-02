# 本地 .env 密钥轮换执行记录（2026-08-31）

> 对应七维终评高危红线项（`.env` 明文真实密钥）与 `deployment/secret-rotation.md` 全量轮换编排。
> 本记录面向**本地开发库**；生产轮换按同一手册在部署窗口执行。

## 执行步骤与结果

| 步骤            | 命令/动作                                                 | 结果                                                                        |
| --------------- | --------------------------------------------------------- | --------------------------------------------------------------------------- |
| 1. 生成新密钥   | `node scripts/generate-secrets.js --out <仓库外临时目录>` | JWT/JWT_REFRESH/AES/HMAC 等全套生成并通过强度自检                           |
| 2. AES 迁移演练 | `migrate-mfa-secret.js`（新钥经环境变量传入）             | 存量 `enc:v1:` 密文 1 条，失败 0                                            |
| 3. AES 迁移执行 | `--apply`                                                 | 1 条迁移成功、逐条回读校验通过                                              |
| 4. 轮换前链留档 | `verify-audit-chain.js > 留档`                            | total 6497；hash_mismatch 19（既有）；hmac_missing 6；hmac_mismatch 0       |
| 5. HMAC 重签    | `resign-audit-hmac.js --new-key *** --apply`              | 5729 条重签完成                                                             |
| 6. 更新载体     | `.env` 四键替换（旧文件备份于本机临时目录）               | 完成                                                                        |
| 7. 轮换后复核   | `verify-audit-chain.js`                                   | hmac_missing 6→0；**hmac_mismatch 0**；hash_mismatch 19（与轮换前逐条一致） |
| 8. 启动验证     | 新钥启动后端                                              | /health 200，无 MFA 解密/密钥相关错误                                       |

## 结论

- 四把密钥已轮换，旧密钥签发的令牌全部失效（预期行为，重新登录即可）。
- HMAC 轮换零失配；6 条原无 hmac 的记录已补签。
- `hash_mismatch: 19` 为轮换前后完全一致的**开发库既有断链**（历史测试数据所致），
  与本次轮换无关（重签不改写 hash/prevHash）；生产链路受 `withChainLock` 保护，不受此影响。

## 附带核实

- `.gitignore` / `.dockerignore` 均已覆盖 `.env`（含 `.env.*` 变体，`.env.example` 除外）。
- 本目录**不是 git 仓库**，无提交历史可排查（终评中 `git log --all` 历史清理步骤不适用，特此留档）。
- 本地无 `mongodump`，未按手册第 0 步做库备份：开发库数据可再生，迁移脚本逐条回读校验作为兜底。
