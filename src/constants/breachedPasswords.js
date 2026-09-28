/**
 * 常见泄露/弱口令黑名单（G8）
 *
 * 设计取舍：不接入 HaveIBeenPwned 等在线 API——那会把用户密码哈希前缀
 * 发往第三方，且给注册/改密链路引入外部依赖与延迟。改为内置「已通过复杂度
 * 规则但仍属高频撞库口令」的本地清单：这类口令恰好满足大小写+数字+符号，
 * 复杂度校验拦不住，却位于所有撞库字典的前列。
 *
 * 比对侧的归一化在 utils/helpers.isBreachedPassword：小写 + 去空白 +
 * 收敛末尾连续数字，覆盖 Admin@123 / admin@1234 这类同源变体。
 * 清单保持精简可维护，不追求覆盖全部字典。
 */
const BREACHED_PASSWORDS = new Set([
  'admin@123',
  'admin@1234',
  'admin@12345',
  'admin123',
  'password@123',
  'passw0rd!',
  'p@ssw0rd',
  'p@ssword',
  'qwer1234!',
  'qwerty@123',
  'abc@1234',
  'abcd1234!',
  'test@123',
  'root@123',
  'user@123',
  'welcome@123',
  'changeme@1',
  'letmein@123',
  'iloveyou@1',
  'monkey@123',
  'dragon@123',
  'master@123',
  'sunshine@1',
  'football@1',
  'baseball@1',
  '1qaz@wsx',
  '1q2w3e4r!',
  'zaq1@wsx',
  'qazwsx@123',
  'aa123456!',
  'a1234567!',
  '12345678a!',
  'huawei@123',
  'xiaomi@123',
  'china@123',
  'fire@123',
  'fire@1234',
  'xf@123456',
  'admin@qwe',
  'admin@asd',
]);

module.exports = { BREACHED_PASSWORDS };
