/**
 * 测试固件统一出口（fixtures 收敛）
 *
 * 背景：主机地址/来源类字面量曾散落在 10+ 个测试文件里，跨环境
 * （CI 容器/本机/反代演练）运行时存在端口与地址假设风险。
 * 本模块把「环境耦合」的字面量收敛为可经环境变量覆盖的单一来源；
 * 「语义数据」（攻击源、私网段探测值）刻意保留为字面量——
 * 它们是被测对象本身，不应随环境变化。
 *
 * 约定：
 * - 新增共享固件放本目录（大块数据单独成文件，如 users.js）；
 * - 一次性数据就近内联在用例里即可，不必强行集中。
 */

const { DEFAULT_CLIENT_IP, DEFAULT_CORS_ORIGIN } = require('../constants');

// 审计/请求类固件里的客户端 IP：仅表示「一条落库的客户端地址」，
// 不参与真实网络行为；TEST_CLIENT_IP 可在特殊环境下覆盖
const TEST_CLIENT_IP = process.env.TEST_CLIENT_IP || DEFAULT_CLIENT_IP;

// 前端来源白名单。默认值取自 constants.js，与 globalSetup.js / setup.js 的
// CORS_ORIGIN 同源，避免三处各写一套导致 originCheck 类测试与全局配置漂移
const TEST_FRONTEND_ORIGIN_LOCALHOST = process.env.TEST_FRONTEND_ORIGIN || DEFAULT_CORS_ORIGIN;
const TEST_FRONTEND_ORIGIN_LOOPBACK = TEST_FRONTEND_ORIGIN_LOCALHOST.replace(
  'localhost',
  '127.0.0.1'
);

// 攻击者来源（语义数据：测「外部来源被拒」，固定不变）
const EVIL_ORIGIN = 'http://evil.com';

module.exports = {
  TEST_CLIENT_IP,
  TEST_FRONTEND_ORIGIN_LOCALHOST,
  TEST_FRONTEND_ORIGIN_LOOPBACK,
  EVIL_ORIGIN,
};
