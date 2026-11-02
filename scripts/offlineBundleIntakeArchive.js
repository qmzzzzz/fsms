/**
 * inbox 归档的生命周期：外层签名路径、落位成功后的消费（移入 `.processed/`）。
 *
 * 单独成文件而不是留在 `offlineBundleIntake.js`：后者已贴 max-lines 棘轮上限，
 * 而这里的判据（同目录 rename、签名一并移动、失败只告警）不参与任何落位判定，
 * 拆开后两边都只承担一件事。
 */

const fs = require('fs');
const path = require('path');

/** 外层签名的路径：归档名 + .sig（`pkg.tar.gz` → `pkg.tar.gz.sig`） */
const signaturePathOf = (archivePath) => `${archivePath}${'.sig'}`;

/**
 * 落位成功后已消费归档的存放目录（inbox 下的点子目录）。
 *
 * 必须把归档移出 inbox：candidates[0] 永远是字典序第一个文件，落位完成后若原样留在
 * inbox，下一轮仍会选中它，又因目标目录已存在而 aborted_target_exists——后续包永远
 * 轮不到，且每 15s 重做一次静默期、sha256 与 tar 列表并写一份留痕。移入同级点子目录
 * 而不是删除：留一份原件便于审计与重放，且同目录 rename 不受跨文件系统限制。
 */
const PROCESSED_DIR_NAME = '.processed';

/**
 * 消费一个已落位的归档（归档 + 外层签名一起移入 `.processed/`）。
 *
 * @param {string} archivePath 已落位的归档路径
 * @param {object} opts
 * @param {number} opts.dirMode `.processed/` 的权限（与 inbox 同纪律，由调用方给单一常量）
 * @returns {string[]} 实际移动的文件名
 */
function consumeArchive(archivePath, { dirMode }) {
  const dir = path.join(path.dirname(archivePath), PROCESSED_DIR_NAME);
  fs.mkdirSync(dir, { recursive: true, mode: dirMode });
  const moved = [];
  for (const file of [archivePath, signaturePathOf(archivePath)]) {
    if (!fs.existsSync(file)) continue;
    const target = path.join(dir, path.basename(file));
    fs.renameSync(file, target);
    moved.push(path.basename(target));
  }
  return moved;
}

/**
 * 落位成功后的消费步骤（fail-soft：失败只告警、不改判落位结果）。
 * 落位本身已经成功，删不掉原件是「下轮会重试」，不该把一次成功的升级包判成失败。
 *
 * @param {object} ctx
 * @param {string} ctx.archive inbox 里的归档路径
 * @param {object} ctx.state intake 结果状态（写入 consumed / consumeWarning）
 * @param {Function} ctx.step 步骤留痕回调
 * @param {Function} ctx.warn 告警回调
 * @param {number} ctx.dirMode `.processed/` 的权限
 */
function consumeAfterPromote({ archive, state, step, warn, dirMode }) {
  step('consume-archive');
  try {
    state.consumed = consumeArchive(archive, { dirMode });
  } catch (err) {
    state.consumeWarning = `归档移出 inbox 失败：${err.message}`;
    warn(state.consumeWarning);
  }
}

module.exports = {
  PROCESSED_DIR_NAME,
  consumeAfterPromote,
  consumeArchive,
  signaturePathOf,
};
