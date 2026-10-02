/**
 * 一次性开发密钥隔离（e2e / 压测 / 生产演练三个 harness 专用）
 *
 * 背景：`src/config/index.js:10-11` 在 require 期就调 `hydrateSecretsFromFiles()`，
 * 而冲突规则是**文件优先**（`src/config/secrets.js:113` 无条件 `process.env[name] = value`）。
 * 三个 harness 的模式是「先设一次性 env，再 require ../src/index.js」
 * （index.js 为 require 即启动，见 e2e-smoke.js 头注释）。于是只要宿主上还留着
 * `*_FILE`，回填就会把 harness 刚设好的 `MONGODB_URI` / `JWT_SECRET` / `AES_SECRET_KEY`
 * 等覆写成**真实密钥与真实库连接串**，而 harness 自己毫无察觉。
 *
 * 后果不是测试难看不通过，是**写**：`npm run test:e2e` 会向那个库播种管理员、
 * 建用户、发告警；`npm run test:load` 会打五相压测流量并写审计。
 *
 * `*_FILE` 有两个来源，两条都必须堵（第一版只堵了第一条，实测被打回）：
 *   1) 宿主 shell 里 export 过——跑运维脚本时顺手导出的。
 *      deployment/secret-rotation.md 要求「每条命令都必须自带 *_FILE 前缀」，
 *      把它 export 起来是自然且更省事的做法，所以这条会被踩到；
 *   2) `.env` 里写着 `*_FILE`——`.env.example:12` 的生产口径 b)「只配 *_FILE，
 *      本文件不写同名明文变量」正是这个形状。关键在时序：dotenv 在 hydrate 的
 *      **前一行**（src/config/index.js:6 → :11），所以守卫跑在那之前时，
 *      `process.env` 里根本还没有这些键，"只看当前有没有"的守卫会漏掉整条路径。
 *      因此本函数**无条件**为 FILE_BACKED_SECRETS 全量置空（预防 dotenv 回填），
 *      并先自己 require 一次 dotenv，把 .env 里的 *_FILE 读出来用于告警。
 *
 * 为什么是**置空**而不是 delete：`delete process.env.X_FILE` 之后，
 * dotenv（src/config/index.js:6 再次执行）发现该键不存在，就把 `.env` 里的值填回来，
 * 守卫形同没做；置空对 dotenv 是"已定义"（16.6.1 不覆盖已定义键），
 * 对 hydrate 是 `secrets.js:71` 的 `!filePath` ⇒ 跳过。两条都实测（见
 * src/tests/config/disposableSecretIsolation.test.js 的 A/B 与 delete 反证）。
 *
 * 不做的两个替代方案（理由记在这里，避免下次重走）：
 *   · 用 NODE_ENV 跳过回填：production-drill.js 自己要 `NODE_ENV=production`，
 *     跳过就等于演练不再具备生产同构性，而那正是它存在的意义。
 *   · 把 hydrate 改成"环境变量优先"：那会推翻一个深思熟虑的安全决定——
 *     挂载的 secret 必须压过可能残留的 `.env` 明文，否则轮换看起来生效实则没生效。
 */

const { FILE_BACKED_SECRETS } = require('../src/config/secrets');

/**
 * 把宿主上（或 `.env` 里）残留的 `*_FILE` 就地置空，
 * 让后续 require 到 src/config 的一次性进程只能用自己在内存里生成的密钥与临时库。
 *
 * 清单从 `FILE_BACKED_SECRETS` 派生（不是抄一份字面量），
 * 所以将来新增可文件注入的密钥名会自动被覆盖。
 *
 * @param {{scriptName: string}} opts 调用方脚本名，只用于告警可读
 * @returns {Array<{name: string, filePath: string}>} 原本带值、被清掉的条目
 *          （空数组表示宿主本来就很干净；注意返回的条目少，置空的动作是全量的）
 */
function isolateDisposableSecrets({ scriptName }) {
  // 与 src/config/index.js:6 同模块同默认路径（cwd/.env），避免自己写一套解析。
  // 这一步只为了让 .env 里的 *_FILE 出现在 process.env 上、从而被下面的循环清掉
  // 并写进告警；值本身随后也会被 harness 的一次性值覆盖或保持原样，与不做这步等价。
  require('dotenv').config();

  const isolated = [];
  for (const name of FILE_BACKED_SECRETS) {
    const filePathVar = `${name}_FILE`;
    const filePath = process.env[filePathVar];
    if (filePath !== undefined && String(filePath).trim() !== '') {
      isolated.push({ name, filePath: String(filePath) });
    }
    process.env[filePathVar] = '';
  }

  if (isolated.length === 0) return isolated;

  // 告警必须有：静默吞掉运维显式配置的 *_FILE 是另一种误导
  // （他会以为 harness 跑的是挂载密钥的那套配置）。
  // 值本身是路径不是密钥，可以打出来帮助定位来源。
  const lines = isolated.map((i) => `    ${i.name}_FILE=${i.filePath}`).join('\n');
  console.warn(
    `[${scriptName}] 检测到 ${isolated.length} 个 *_FILE 密钥注入项（宿主环境变量或 .env），已置空：\n` +
      `${lines}\n` +
      `  原因：本脚本用的是内存临时库与一次性随机密钥；若沿用这些 *_FILE，\n` +
      `  src/config/secrets.js 会在启动期把一次性密钥覆写成文件里的真实值，\n` +
      `  于是冒烟/压测流量会打到真实库上。宿主侧需要 *_FILE 时请只给单条命令加前缀，\n` +
      `  不要 export，也不要写进 .env（那是 .env.example:12 的生产口径 b，\n` +
      `  在这里会把一次性进程接回真实密钥）。`
  );
  return isolated;
}

module.exports = { isolateDisposableSecrets };
