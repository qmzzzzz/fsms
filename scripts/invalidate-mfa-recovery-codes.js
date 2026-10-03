/**
 * MFA 恢复码批量作废（2026-10-01 审计 finding #4 的收尾件）
 *
 * 用法（与 migrate-mfa-secret.js / migrate-pii-encryption.js 同族门禁口径）：
 *   node scripts/invalidate-mfa-recovery-codes.js                 # 演练：只统计并出报告
 *   ALLOWED_SOURCE_DB=<库名> node scripts/invalidate-mfa-recovery-codes.js --apply --yes
 *                                                                 # 清空全部存量恢复码
 *
 * 背景（deployment/secret-rotation.md 第 3 点）：mfaService.hashRecoveryCode 用
 * HMAC_SECRET 作 pepper 对恢复码做摘要，**换钥后存量摘要一条都对不上**——
 * 恢复码是用户丢失认证器时的唯一逃生门，这个故障只会在那个最坏时刻才暴露：
 * 用户输入正确的恢复码却得到「恢复码错误」，且无任何服务端信号说明是轮换所致。
 * 明文码生成后不保留，摘要无法重算（与口令历史同处境），处置只能是作废 + 用户重新生成。
 *
 * 为什么「作废」而非「保留等过期」：留着打不开的摘要没有任何安全或可用性价值，
 * 反而让「该用户还有恢复码」的库内状态变成谎言——清成空数组后，"无恢复码"是
 * 可判定的显式状态（与 User.mfaRecoveryCodes 的 default: [] 同形态），用户中心
 * 与管理端据此提示重新生成，而不是让用户在最坏时刻撞上一条永不命中的验证。
 *
 * 安全属性（同族纪律）：
 *   - 演练模式一行不改，报告先行（多少用户受影响）；
 *   - --apply 需 ALLOWED_SOURCE_DB 白名单 + --yes 双确认（destructiveGuard），
 *     被拒绝的执行不向目标库握手；
 *   - 写入后**回读自证**：清零后再次统计非空行数必须为 0，不为 0 以非零退出——
 *     "批量写成功但漏改"比失败更危险。
 */

'use strict';

const mongoose = require('mongoose');
require('../src/config/secrets').hydrateSecretsFromFiles();
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');

function parseArgs() {
  const args = { apply: false, confirmYes: false };
  for (const a of process.argv.slice(2)) {
    if (a === '--apply') args.apply = true;
    if (a === '--yes') args.confirmYes = true;
  }
  return args;
}

/** 「还持有恢复码」的统一判据：数组存在且至少有一条摘要（演练/回读共用） */
const HOLDING_FILTER = { mfaRecoveryCodes: { $exists: true, $not: { $size: 0 } } };

async function main() {
  const args = parseArgs();

  const { uri, dbName, host, isFallback } = resolveMongoUri({
    scriptName: 'invalidate-mfa-recovery-codes.js',
  });
  if (
    !assertApplyAllowed({
      scriptName: 'invalidate-mfa-recovery-codes.js',
      dbName,
      host,
      isFallback,
      apply: args.apply,
    })
  ) {
    process.exit(2);
  }
  if (args.apply && !args.confirmYes) {
    console.error(
      '错误：--apply 将清空所有用户的 MFA 恢复码（不可逆；用户需重新生成），需再传 --yes 确认。'
    );
    process.exit(2);
  }

  await mongoose.connect(uri);
  const coll = mongoose.connection.collection('users');

  const holding = await coll.countDocuments(HOLDING_FILTER);
  const sample = await coll
    .find(HOLDING_FILTER, { projection: { _id: 1 } })
    .limit(5)
    .toArray();

  if (args.apply && holding > 0) {
    const result = await coll.updateMany(HOLDING_FILTER, { $set: { mfaRecoveryCodes: [] } });
    // 回读自证：清零后不允许再有任何非空行。不为 0 = 改写不完整（并发写入/过滤器
    // 漂移），以非零退出让调用方无法把它当成功收场。
    const leftover = await coll.countDocuments(HOLDING_FILTER);
    console.log(
      JSON.stringify(
        {
          mode: 'APPLY',
          cleared: result.modifiedCount,
          leftoverAfterRewrite: leftover,
          sampledBefore: sample.map((d) => String(d._id)),
        },
        null,
        2
      )
    );
    if (leftover > 0) {
      console.error(
        `\n✗ 清空后仍有 ${leftover} 个用户持有恢复码——本次改写不完整，请人工核查后再跑一次演练。`
      );
      await mongoose.disconnect();
      process.exit(1);
    }
    console.log(
      '\n✅ 存量恢复码已全部作废。请按 deployment/secret-rotation.md 第 3 点：' +
        '提示持有 MFA 的用户重新生成恢复码（用户中心 → MFA → 恢复码）。'
    );
  } else {
    console.log(
      JSON.stringify(
        {
          mode: 'DRY-RUN（未改写任何记录）',
          usersHoldingRecoveryCodes: holding,
          sampled: sample.map((d) => String(d._id)),
        },
        null,
        2
      )
    );
    console.log('\n演练模式未改写任何记录。加 --apply --yes（并配置 ALLOWED_SOURCE_DB）执行。');
  }

  await mongoose.disconnect();
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
