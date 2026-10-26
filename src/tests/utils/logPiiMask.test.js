/**
 * 运行日志 PII 掩码（O-1）——判据与边界的可证伪测试
 *
 * 这个模块的失败形态全是"看起来正常"：
 *   · 正则写宽了 ⇒ 把订单号、时间戳掩成星号，排障时看不出发生了什么；
 *   · 正则写窄了 ⇒ 换个号码格式就漏，而漏掉的日志和正常的日志长得一样；
 *   · 掩码顺序反了 ⇒ 身份证被手机号规则切一刀，得到既不可读也不合规的残形；
 *   · 只处理顶层 ⇒ `{ user: { email } }` 这种最常见形状完全漏过。
 * 所以这里逐条钉形状（不是"包含 ***"这种恒真断言），并给出反向对照
 * （`LOG_PII_MASK=false` 时必须**不**掩码——否则"掩码生效"可能只是断言写错了）。
 */

'use strict';

const { REDACTED, isSensitiveKey, maskPiiText, maskLogInfo } = require('../../utils/logPiiMask');
const logger = require('../../utils/logger');

describe('PII 文本掩码（O-1）', () => {
  test('email：保留首字符与域名，本地部分挖空', () => {
    expect(maskPiiText('用户 zhangsan@corp.example.com 登录失败')).toBe(
      '用户 z***@corp.example.com 登录失败'
    );
    // 单字符本地部分也要能命中（`a@b.co`）
    expect(maskPiiText('a@b.co')).toBe('a***@b.co');
  });

  test('手机号：保留前 3 后 4，中间四位挖空', () => {
    expect(maskPiiText('手机 13812345678 已绑定')).toBe('手机 138****5678 已绑定');
  });

  test('身份证：保留前 6 后 4，且必须**先于**手机号规则', () => {
    // 若顺序反了，18 位里那 11 位连续数字会先被手机号规则吃掉，得到残形
    expect(maskPiiText('110101199003071234')).toBe('110101********1234');
    // 末位 X 形态
    expect(maskPiiText('11010119900307123X')).toBe('110101********123X');
  });

  test('不误伤：短数字、长数字串中段、普通业务文本保持不变', () => {
    const untouched = [
      '订单号 202610260001', // 14 位，不是手机号也不是身份证
      '耗时 1234567890123 ms', // 长数字串：不得命中中段
      'tokenVersion=3 已失效',
      'route=/api/reports/export status=200',
      '设备编号 DEV-001',
    ];
    for (const text of untouched) {
      expect(maskPiiText(text)).toBe(text);
    }
  });

  test('非字符串输入原样返回（调用点可能传 undefined/null）', () => {
    expect(maskPiiText(undefined)).toBe(undefined);
    expect(maskPiiText(null)).toBe(null);
    expect(maskPiiText(42)).toBe(42);
    expect(maskPiiText('')).toBe('');
  });
});

describe('凭据字段整体替换（O-1）', () => {
  test('键名归一：camelCase / snake_case / 大写都算同一个凭据', () => {
    for (const key of ['password', 'old_password', 'newPassword', 'ACCESS_TOKEN', 'x-api-key']) {
      expect(isSensitiveKey(key)).toBe(true);
    }
  });

  test('版本号与业务词不算凭据（否则排障信息被无谓吃掉）', () => {
    for (const key of ['tokenVersion', 'userId', 'username', 'requestId', 'email']) {
      expect(isSensitiveKey(key)).toBe(false);
    }
  });

  test('值是对象时整体替换：只处理字符串等于放过 { user, pass } 这种形状', () => {
    const info = {
      message: '登录',
      credentials: { username: 'admin', password: 'PlainText123' },
      authorization: 'Bearer abc.def.ghi',
    };
    maskLogInfo(info);
    expect(info.credentials).toBe(REDACTED);
    expect(info.authorization).toBe(REDACTED);
    expect(JSON.stringify(info)).not.toContain('PlainText123');
    expect(JSON.stringify(info)).not.toContain('abc.def.ghi');
  });

  test('嵌套对象与数组里的 PII 也要掩（最常见形状是请求体片段）', () => {
    const info = {
      message: '创建用户',
      payload: {
        user: { email: 'lisi@corp.com', phone: '13900001111' },
        items: [{ contact: 'wangwu@corp.com' }],
      },
    };
    maskLogInfo(info);
    expect(JSON.stringify(info)).not.toContain('lisi@corp.com');
    expect(JSON.stringify(info)).not.toContain('13900001111');
    expect(JSON.stringify(info)).not.toContain('wangwu@corp.com');
    // 形状仍然可辨识：能看出"这里原本是个邮箱"
    expect(info.payload.user.email).toBe('l***@corp.com');
  });

  test('结构性键不掩：userId/requestId 是排障关联键，掩掉等于把日志变成碎片', () => {
    const info = { message: 'x', requestId: 'req-123', userId: '507f1f77bcf86cd799439011' };
    maskLogInfo(info);
    expect(info.requestId).toBe('req-123');
    expect(info.userId).toBe('507f1f77bcf86cd799439011');
  });

  test('循环引用不抛错（掩码阶段不得先于 serializeMeta 炸掉一条日志）', () => {
    const info = { message: 'x', a: {} };
    info.a.self = info.a;
    expect(() => maskLogInfo(info)).not.toThrow();
    expect(info.a.self).toBe(info.a);
  });

  test('深度上限：超过 4 层的对象不再递归（日志 meta 再深也没有排障价值）', () => {
    const info = { message: 'x' };
    let cursor = info;
    for (let i = 0; i < 6; i += 1) {
      cursor.next = {};
      cursor = cursor.next;
    }
    cursor.email = 'deep@corp.com';
    maskLogInfo(info);
    // 第 5 层之后不处理：这是**已知边界**，写在这里以免被当成缺陷
    expect(JSON.stringify(info)).toContain('deep@corp.com');
  });

  test('关闭开关：LOG_PII_MASK=false 时原文保留（反向对照）', () => {
    const saved = process.env.LOG_PII_MASK;
    process.env.LOG_PII_MASK = 'false';
    try {
      const info = { message: '联系 zhangsan@corp.com', password: 'Plain123' };
      maskLogInfo(info);
      expect(info.message).toBe('联系 zhangsan@corp.com');
      expect(info.password).toBe('Plain123');
    } finally {
      if (saved === undefined) delete process.env.LOG_PII_MASK;
      else process.env.LOG_PII_MASK = saved;
    }
  });
});

describe('与 logger 清洗链的集成（O-1）', () => {
  test('sanitizeLogInfo：先清洗控制字符/截断，再掩码，两步都在', () => {
    const info = {
      message: '用户 zhangsan@corp.com 提交\n伪造行',
      phone: '13812345678',
      password: 'Plain123',
    };
    logger.__test.sanitizeLogInfo(info);
    expect(info.message).not.toContain('\n'); // 控制字符仍被清
    expect(info.message).toContain('z***@corp.com'); // PII 已掩
    expect(info.phone).toBe('138****5678');
    expect(info.password).toBe(REDACTED);
  });

  test('超长 message 仍然被截断（掩码不得把长度上限顶掉）', () => {
    const info = { message: 'a'.repeat(9000) };
    logger.__test.sanitizeLogInfo(info);
    expect(info.message.length).toBeLessThanOrEqual(8192);
  });
});
