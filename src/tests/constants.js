/**
 * 测试基础常量（单一来源）
 *
 * 背景：globalSetup.js（进程级，先于 Jest 运行）与 setup.js（每个测试文件
 * 执行前运行）都要在测试环境就绪前写入同一套环境变量。此前两处各写一遍
 * 字面量（含 CORS 来源与三把测试密钥），改一处忘一处就会出现「全局已设、
 * 单文件回退默认值」的漂移——这类症状只在特定执行顺序下暴露，极难定位。
 *
 * 本模块不读 process.env、不产生任何副作用，因此可被 globalSetup 安全引入
 * （globalSetup 运行在 Jest 环境之外，不能依赖 setup 阶段才就绪的东西）。
 *
 * 约定：
 * - 放这里的都是「环境装配用的默认值」；
 * - 被测对象本身的语义数据（私网段探测值、攻击来源等）属于 fixtures 职责，
 *   刻意保留为字面量，不收进来。
 */

// 前端来源白名单默认值。fixtures 的 TEST_FRONTEND_ORIGIN_* 由此派生，
// 保证 originCheck 类测试与全局配置同源。
const DEFAULT_CORS_ORIGIN = 'http://localhost:3001';

// 审计/请求固件里的客户端 IP：仅表示「一条落库的客户端地址」，不参与真实网络行为
const DEFAULT_CLIENT_IP = '127.0.0.1';

// 测试专用密钥：长度与格式要求与生产一致（配置强校验会检查），
// 但仅为固定字面量，任何情况下都不得复用于生产环境。
// 生产密钥请用 scripts/generate-secrets.js 生成。
const TEST_JWT_SECRET = 'test-jwt-secret-12345678901234567890';
const TEST_AES_SECRET_KEY = 'test-aes-key-12345678901234567890123456789012';
const TEST_HMAC_SECRET = 'test-hmac-secret-1234';

module.exports = {
  DEFAULT_CORS_ORIGIN,
  DEFAULT_CLIENT_IP,
  TEST_JWT_SECRET,
  TEST_AES_SECRET_KEY,
  TEST_HMAC_SECRET,
};
