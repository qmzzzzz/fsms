/**
 * docker-compose.yml 的「代码视图」工具
 *
 * 为什么需要：本仓有两条判据是**从 compose 反向推导**清单的——
 *   · `deployScript.test.js`：preflight 必须覆盖 compose 里每个 `${VAR:?}`；
 *   · `deployWorkflow.test.js`：每个 `${VAR:?}` 都要由两条部署路径下发。
 * 两者都直接对 compose 源码跑正则。问题是**注释里也会出现同样的写法**：
 * `app-green` 的注释就解释了「为什么这里不用 `${APP_IMAGE_NEXT:?}`」，
 * 于是那个变量被当成真实硬必填项，两条判据一起要求给它补 preflight 与工作流下发——
 * 而它**恰恰不该**硬必填（compose 在 profile 过滤之前做插值，加 `:?` 会让
 * 日常 `docker compose up` 直接失败）。判据把"说明为什么不用它"读成了"用了它"。
 *
 * 这与本仓 `tests/helpers/jsCodeOnly` 是同一条纪律：判据只看代码，不看注释。
 * 两份测试共用这一份实现，避免两处各写一个"顺手"的剥离函数再各自漂移。
 */

/**
 * 剥掉整行 YAML 注释。
 *
 * 口径只覆盖**整行注释**（`#` 是该行第一个非空白字符），不处理行尾 `# …`：
 * 行尾注释要正确剥离必须懂引号与转义（`password: 'a#b'` 里的 `#` 不是注释），
 * 而本仓的 compose 里 `:?` 形态从未出现在行尾注释中——为一个不存在的形态
 * 引入半个 YAML 解析器，比不处理更容易错。真出现时，先在这里补判据再改断言。
 *
 * 注意用 `[^\n]*` 而不是 `.*`：`. `不匹配 `\r`，CRLF 文件上 `#.*$` 会整条失配
 * （本仓 compose 是 CRLF，实测过这个坑），表现为"剥了等于没剥"。
 *
 * @param {string} src compose 源码
 * @returns {string} 去注释后的源码（保留换行，行号不变）
 */
const stripYamlLineComments = (src) => src.replace(/^[ \t]*#[^\n]*/gm, '');

/**
 * 提取 compose 里声明的「硬必填」变量名（`${VAR:?}`），去重后按出现顺序返回。
 *
 * @param {string} yml compose 源码
 * @returns {string[]} 变量名
 */
const hardRequiredEnv = (yml) => [
  ...new Set([...stripYamlLineComments(yml).matchAll(/\$\{([A-Z0-9_]+):\?/g)].map((m) => m[1])),
];

module.exports = { stripYamlLineComments, hardRequiredEnv };
