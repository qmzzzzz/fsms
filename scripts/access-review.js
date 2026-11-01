#!/usr/bin/env node
/**
 * 定期权限复核巡检（C-08）
 *
 * 输出临时授权的复核汇总与超期清单；--expire 时先执行到期回收（把到期的 active
 * 置为 expired，记录留存不删除）。到期判定的权威在读侧，本脚本只负责让状态字段
 * 与事实一致，不承担「到期即失效」的职责。
 *
 * 复核动作（2026-10-30 补，--review）：巡检**默认只读**；只有显式传
 * `--review <grantId> --reviewer <username|ObjectId>` 才写一处 reviewedAt/reviewedBy。
 * 接线理由（work/fix-round3-services.md ③ / work/audit-round3-services.md §1.3）：
 * accessReviewService.markReviewed 此前**零调用** ⇒ reviewedAt 永远写不进去 ⇒
 * 超期清单只增不减、--fail-on-overdue 长期常红。选脚本而不是新增 HTTP 端点：
 *   ① 运维动作本来就是「看一眼超期清单 → 确认后标记」，--fail-on-overdue 的消费者
 *      就是本脚本；
 *   ② 不新增路由/权限码，GET 只读语义天然不被破坏（写入口只存在于显式 CLI 参数之后）。
 * --reviewer 必填（而不是可空）：service 的 reviewedBy 是「复核人留痕」的一半，
 * reviewedBy: null 等于没人认领这次复核——宁可拒绝执行也不留一条无主记录。
 *
 * 退出码：默认 0；带 --fail-on-overdue 且存在超期未复核授予时退出 1，
 * 供 cron/systemd timer 与告警链路使用；参数/执行失败退出 2（与判据结果分开）。
 */

'use strict';

const mongoose = require('mongoose');
const config = require('../src/config');
const logger = require('../src/utils/logger');

const argv = process.argv.slice(2);
const shouldExpire = argv.includes('--expire');
const failOnOverdue = argv.includes('--fail-on-overdue');

/** ObjectId 形态（与仓内其它脚本同口径：24 位十六进制） */
const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;

/** 取 `--name value` 或 `--name=value`；未传返回 null（与「传了空值」区分） */
function readArgValue(name) {
  const eq = argv.find((a) => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const i = argv.indexOf(name);
  if (i >= 0) return argv[i + 1] || '';
  return null;
}

/**
 * 解析并校验复核参数：缺值/非法值直接退出 2，不做「参数没生效但看起来生效」的
 * 静默回退（同仓 resign-audit-chain-v3.js 的 parseArgs 纪律）。
 */
function resolveReviewArgs() {
  const grantId = readArgValue('--review');
  if (grantId === null) return null;
  const reviewer = readArgValue('--reviewer');
  const problems = [];
  if (!OBJECT_ID_RE.test(grantId)) problems.push('--review 需要 24 位十六进制 ObjectId');
  if (!reviewer)
    problems.push('--review 必须同时给 --reviewer <username|ObjectId>（复核要留痕复核人）');
  else if (!OBJECT_ID_RE.test(reviewer) && reviewer.length > 50)
    problems.push('--reviewer 用户名过长');
  if (problems.length > 0) {
    logger.error('复核参数无效', { problems });
    process.exit(2);
  }
  return { grantId, reviewer };
}

/** username 或 ObjectId → 复核人 userId；查不到 ⇒ 上抛（由 main 的 catch 转 exit 2） */
async function resolveReviewerUserId(reviewer) {
  if (OBJECT_ID_RE.test(reviewer)) return reviewer;
  const User = require('../src/models/User');
  const found = await User.findOne({ username: reviewer }).select('_id').lean();
  if (!found) throw new Error(`复核人不存在：${reviewer}`);
  return found._id;
}

async function main() {
  const review = resolveReviewArgs();
  await mongoose.connect(config.mongodbUri);
  const privilegeGrantService = require('../src/services/privilegeGrantService');
  const accessReviewService = require('../src/services/accessReviewService');

  const expired = shouldExpire ? await privilegeGrantService.expireDue() : 0;
  const summary = await accessReviewService.reviewSummary({});
  const overdue = await accessReviewService.listOverdueGrants({ limit: 100 });

  // 复核写动作只在显式参数后发生：没有 --review 时本脚本对数据零副作用
  let reviewed = null;
  if (review) {
    const reviewerId = await resolveReviewerUserId(review.reviewer);
    const grant = await accessReviewService.markReviewed({
      grantId: review.grantId,
      operator: { userId: reviewerId },
    });
    reviewed = {
      id: String(grant._id),
      reviewedAt: grant.reviewedAt,
      reviewedBy: grant.reviewedBy ? String(grant.reviewedBy) : null,
    };
    logger.warn('已登记临时授权复核', { grantId: reviewed.id, reviewedBy: reviewed.reviewedBy });
  }

  const report = {
    expired,
    summary,
    overdueGrants: overdue.map((grant) => ({
      id: String(grant._id),
      username: grant.username,
      codes: grant.permissionCodes,
      grantedAt: grant.grantedAt,
      expiresAt: grant.expiresAt,
      highRisk: grant.highRisk,
    })),
    reviewed,
  };
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');

  if (failOnOverdue && summary.overdue > 0) {
    logger.warn('存在超期未复核的临时授权', { overdue: summary.overdue });
    return 1;
  }
  return 0;
}

main()
  .then((code) => mongoose.connection.close().then(() => process.exit(code)))
  .catch((error) => {
    logger.error('权限复核巡检失败', { message: error.message });
    process.exit(2);
  });
