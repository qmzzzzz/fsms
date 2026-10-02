/**
 * 轮换类脚本的密钥来源：`--<flag>-file <路径>` 或环境变量，二者都不取"命令行上的值"
 *
 * 为什么值得单独成文件：`--new-key <KEY>` 把密钥写进 argv，于是同一个值同时出现在
 *   · `/proc/<pid>/cmdline` —— Linux 默认 0444，**同机任意本地用户**可读，而一次全量迁移
 *     要跑几分钟，窗口足够长；`ps(1)` / 任务管理器同样一眼可见；
 *   · shell 历史（`HISTCONTROL=ignorespace` 只是"记得在前面加空格"的人为约定，不是机制）；
 *   · 任何 `set -x` 的 CI 日志。
 * 仓里其余密钥早已统一成 `<NAME>_FILE` 口径（`src/config/secrets.js`），只有密钥轮换这一族
 * 还留着 argv 形态——同一门安全要求上的两个标准。这里把"值"换成"路径"，判据向 shell 侧的
 * `mongo_hydrate_uri`（scripts/mongoUri.sh）看齐：单行、纯可打印 ASCII、去 UTF-8 BOM 与
 * CR/尾空白；读不到、多行、含空白或控制字符 ⇒ 硬失败，绝不"取第一条非空行"蒙过去。
 *
 * 所有错误信息只点名**标签与路径**，绝不回显文件内容或环境变量值：一条"密钥泄漏"的报错
 * 如果把密钥再打一遍，就是把它从 argv 换成了 stdout/stderr（CI 日志的保留时间通常更长）。
 */

const fs = require('fs');

/** 合法密钥字符集：0x21–0x7E（可打印 ASCII，不含空格）。与 shell 侧 tr -d '\041-\176' 同判据。 */
const OUT_OF_RANGE = /[^\x21-\x7e]/;

/**
 * 读一个"密钥文件"：必须恰好一行非空内容，且是单行纯可打印 ASCII。
 * 抛错而非退出：调用方决定退出码（本仓 usage 错误一律 exit 2）。
 *
 * @param {string} filePath 命令行上点名的路径
 * @param {string} label 人类可读的密钥名（只用于报错，如「新 AES 密钥」）
 * @returns {string}
 */
function readSecretFile(filePath, label) {
  if (typeof filePath !== 'string' || filePath.trim() === '') {
    throw new Error(`${label} 的文件路径为空（--*-file 需要跟一个路径参数）`);
  }
  let body;
  try {
    body = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    // 只打 err.code：ENOENT/EACCES/EISDIR 足以定位问题，而 message 在部分平台会带上多余信息
    throw new Error(`${label} 文件读取失败：${filePath}（${err.code || '未知原因'}）`);
  }
  const lines = body
    .replace(/^\uFEFF/, '')
    .split(/\r?\n/)
    .filter((l) => l.trim() !== '');
  if (lines.length !== 1) {
    throw new Error(`${label} 文件应为 1 行非空内容，实际 ${lines.length} 行：${filePath}`);
  }
  const value = lines[0].trim();
  if (OUT_OF_RANGE.test(value)) {
    throw new Error(
      `${label} 文件里的密钥含空白或不可打印字符（应为单行纯 ASCII，不要换行、缩进或 BOM）：${filePath}` +
        `。\n   密钥本身不是 ASCII 的话请改用环境变量提供（env 不经 /proc/<pid>/cmdline，不在这条禁令范围）`
    );
  }
  return value;
}

/**
 * 解析一个密钥来源。优先级与 shell 侧一致：**显式 `--*-file` 赢过环境变量**——
 * 命令行点名的是"这一次轮换要用的值"，不能被 shell 里残留的同名环境变量悄悄改写；
 * 两者都给时打一行提示到 stderr（不打印值）。
 *
 * @param {{filePath?: string, envValue?: string, label: string, flagName: string, envName: string}} opts
 * @returns {string} 密钥值
 * @throws {Error} 两个来源都没有，或文件形状不认识
 */
function resolveSecretSource({ filePath, envValue, label, flagName, envName }) {
  if (filePath !== undefined && filePath !== null) {
    if (envValue) {
      console.error(
        `提示：${envName} 与 ${flagName} 同时存在，按 ${flagName} 指定的文件执行（忽略环境变量）`
      );
    }
    return readSecretFile(filePath, label);
  }
  if (envValue) return envValue;
  throw new Error(
    `缺少${label}：请用 ${flagName} <路径> 提供（推荐：密钥不进命令行），或设置 ${envName} 环境变量`
  );
}

module.exports = { readSecretFile, resolveSecretSource };
