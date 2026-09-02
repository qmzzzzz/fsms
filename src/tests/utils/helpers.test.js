/**
 * 公共工具函数测试 — 补齐密码强度、排序校验、escapeRegExp 全字符集覆盖
 */

const {
  escapeRegExp,
  normalizePagination,
  validatePasswordStrength,
  isBreachedPassword,
  validateSort,
  validateEnum,
  stripControlChars,
  stripControlCharsDeep,
  sanitizeSpreadsheetCell,
  parseDateBoundary,
  buildDateRangeFilter,
} = require('../../utils/helpers');

describe('Helper Utils', () => {
  describe('escapeRegExp', () => {
    test('should escape special regex characters', () => {
      expect(escapeRegExp('test[0]')).toBe('test\\[0\\]');
    });

    test('should escape dots', () => {
      expect(escapeRegExp('hello.world')).toBe('hello\\.world');
    });

    test('should escape asterisks', () => {
      expect(escapeRegExp('a*b')).toBe('a\\*b');
    });

    test('should escape multiple special chars', () => {
      expect(escapeRegExp('a.b*c+d?e')).toBe('a\\.b\\*c\\+d\\?e');
    });

    test('should escape all special regex characters', () => {
      // 覆盖 { } | [ ] \ ^ $ 这些同样需要转义的字符
      expect(escapeRegExp('{}|[]\\^$')).toBe('\\{\\}\\|\\[\\]\\\\\\^\\$');
    });

    test('should handle empty string', () => {
      expect(escapeRegExp('')).toBe('');
    });

    test('should handle string with no special chars', () => {
      expect(escapeRegExp('hello')).toBe('hello');
    });

    test('should handle parentheses', () => {
      expect(escapeRegExp('(test)')).toBe('\\(test\\)');
    });

    test('should handle non-string input (number)', () => {
      expect(escapeRegExp(123)).toBe('123');
    });

    test('should prevent regex injection', () => {
      const malicious = '.*';
      const escaped = escapeRegExp(malicious);
      const regex = new RegExp(escaped);
      expect(regex.test('anything')).toBe(false);
      expect(regex.test('.*')).toBe(true);
    });
  });

  describe('normalizePagination', () => {
    test('should return default values for undefined input', () => {
      const result = normalizePagination(undefined, undefined);
      expect(result.page).toBe(1);
      expect(result.limit).toBe(10);
    });

    test('should return default for NaN values', () => {
      const result = normalizePagination('abc', 'xyz');
      expect(result.page).toBe(1);
      expect(result.limit).toBe(10);
    });

    test('should enforce minimum values', () => {
      const result = normalizePagination('-1', '0');
      expect(result.page).toBe(1);
      expect(result.limit).toBe(10);
    });

    test('should parse valid string numbers', () => {
      const result = normalizePagination('3', '25');
      expect(result.page).toBe(3);
      expect(result.limit).toBe(25);
    });

    test('should enforce maximum limit of 500', () => {
      const result = normalizePagination('1', '1000');
      expect(result.limit).toBe(500);
    });

    test('should enforce maximum page of 10000', () => {
      const result = normalizePagination('99999', '10');
      expect(result.page).toBe(10000);
    });

    test('should accept numeric inputs', () => {
      const result = normalizePagination(2, 50);
      expect(result.page).toBe(2);
      expect(result.limit).toBe(50);
    });
  });

  describe('validatePasswordStrength', () => {
    test('should reject empty password', () => {
      expect(validatePasswordStrength('')).toBeTruthy();
      expect(validatePasswordStrength(null)).toBeTruthy();
      expect(validatePasswordStrength(undefined)).toBeTruthy();
    });

    test('should reject password shorter than 12 characters (L-1)', () => {
      expect(validatePasswordStrength('Ab1!')).toBeTruthy();
      expect(validatePasswordStrength('Abcdef1!')).toBeTruthy(); // 8 位在旧策略下合法，现须拒绝
      expect(validatePasswordStrength('Abcdefgh1!xy')).toBeFalsy(); // exactly 12 chars OK
    });

    test('should reject password without uppercase', () => {
      expect(validatePasswordStrength('abcdef1!')).toBeTruthy();
    });

    test('should reject password without lowercase', () => {
      expect(validatePasswordStrength('ABCDEF1!')).toBeTruthy();
    });

    test('should reject password without digit', () => {
      expect(validatePasswordStrength('Abcdefgh!')).toBeTruthy();
    });

    test('should reject password without special character', () => {
      expect(validatePasswordStrength('Abcdefg1')).toBeTruthy();
    });

    test('should accept strong password', () => {
      expect(validatePasswordStrength('Abcdefgh1!xy')).toBeFalsy(); // null = valid
      expect(validatePasswordStrength('MyStr0ng@Pass')).toBeFalsy();
    });

    test('should reject breached password that passes complexity rules (G8)', () => {
      // 以下口令满足全部复杂度规则（含 12 位长度），只能靠黑名单拦截
      expect(validatePasswordStrength('Admin@123456')).toBeTruthy();
      expect(validatePasswordStrength('Password@123')).toBeTruthy();
      expect(validatePasswordStrength('Welcome@1234')).toBeTruthy();
    });
  });

  describe('isBreachedPassword (G8)', () => {
    test('should match blacklist entries case-insensitively', () => {
      expect(isBreachedPassword('admin@123')).toBe(true);
      expect(isBreachedPassword('ADMIN@123')).toBe(true);
      expect(isBreachedPassword('Admin@123')).toBe(true);
    });

    test('should match trailing-digit variants of blacklist entries', () => {
      expect(isBreachedPassword('Admin@1234')).toBe(true);
      expect(isBreachedPassword('Admin@123456')).toBe(true);
    });

    test('should not flag random strong passwords', () => {
      expect(isBreachedPassword('Vn6$Rw83pKx5')).toBe(false);
      expect(isBreachedPassword('Fire@2026Safe!')).toBe(false);
      expect(isBreachedPassword('Xk7#mQ92vL')).toBe(false);
    });

    test('should handle invalid input safely', () => {
      expect(isBreachedPassword('')).toBe(false);
      expect(isBreachedPassword(null)).toBe(false);
      expect(isBreachedPassword(12345678)).toBe(false);
    });
  });

  describe('validateSort', () => {
    test('should return default for empty input', () => {
      expect(validateSort('', { allowedFields: ['name'] })).toBe('-createdAt');
      expect(validateSort(null, { allowedFields: ['name'] })).toBe('-createdAt');
    });

    test('should accept allowed field', () => {
      expect(validateSort('name', { allowedFields: ['name', 'createdAt'] })).toBe('name');
      expect(validateSort('-name', { allowedFields: ['name', 'createdAt'] })).toBe('-name');
    });

    test('should reject disallowed field', () => {
      expect(validateSort('password', { allowedFields: ['name', 'createdAt'] })).toBe('-createdAt');
    });

    // 外部报告项 7：passwordHash 排序侧信道回归锁定——
    // 非白名单字段（含敏感哈希字段及其任意别名）一律回落默认排序，
    // 攻击者无法借排序结果的位置差异探测哈希值
    test('should reject passwordHash sort injection (side-channel)', () => {
      const opts = {
        allowedFields: [
          'username',
          'email',
          'realName',
          'status',
          'department',
          'createdAt',
          'updatedAt',
          'lastLoginAt',
        ],
      };
      expect(validateSort('passwordHash', opts)).toBe('-createdAt');
      expect(validateSort('-passwordHash', opts)).toBe('-createdAt');
      expect(validateSort('passwordhash', opts)).toBe('-createdAt');
      expect(validateSort('PASSWORDHASH', opts)).toBe('-createdAt');
      expect(validateSort('mfaSecret', opts)).toBe('-createdAt');
      expect(validateSort('mfaRecoveryCodes', opts)).toBe('-createdAt');
    });

    test('should reject field with $ injection', () => {
      expect(validateSort('$gt', { allowedFields: [] })).toBe('-createdAt');
    });

    test('should reject field with . injection', () => {
      expect(validateSort('a.b', { allowedFields: [] })).toBe('-createdAt');
    });

    test('should handle + prefix', () => {
      expect(validateSort('+name', { allowedFields: ['name'] })).toBe('name');
    });
  });

  describe('validateEnum', () => {
    test('合法值原样返回', () => {
      expect(validateEnum('low', ['low', 'medium', 'high'], 'riskLevel')).toBe('low');
    });

    test('空值返回 null（未传参）', () => {
      expect(validateEnum(undefined, ['low', 'medium'], 'riskLevel')).toBeNull();
      expect(validateEnum(null, ['low', 'medium'], 'riskLevel')).toBeNull();
      expect(validateEnum('', ['low', 'medium'], 'riskLevel')).toBeNull();
    });

    test('非法值抛出 400 错误并含明确消息', () => {
      let err;
      try {
        validateEnum('warn', ['low', 'medium'], 'riskLevel');
      } catch (e) {
        err = e;
      }
      expect(err).toBeDefined();
      expect(err.status).toBe(400);
      expect(err.message).toContain('riskLevel');
      expect(err.message).toContain('low/medium');
    });
  });

  describe('stripControlChars', () => {
    test('剥离换行、回车、制表与 NUL 字符', () => {
      expect(stripControlChars('Mozilla\n\rFake-Log-Line')).toBe('Mozilla  Fake-Log-Line');
      expect(stripControlChars('a\u0000b')).toBe('a b');
      expect(stripControlChars('a\tb')).toBe('a b');
    });

    test('非字符串原样返回', () => {
      expect(stripControlChars(123)).toBe(123);
      expect(stripControlChars(null)).toBeNull();
      expect(stripControlChars(undefined)).toBeUndefined();
    });

    test('超长字符串按 maxLength 截断', () => {
      expect(stripControlChars('x'.repeat(50), 10)).toHaveLength(10);
    });
  });

  describe('stripControlCharsDeep', () => {
    test('递归清洗嵌套对象与数组中的字符串', () => {
      const input = { a: 'x\ny', b: { c: ['p\rq', 2] } };
      expect(stripControlCharsDeep(input)).toEqual({ a: 'x y', b: { c: ['p q', 2] } });
    });

    test('对象键名同样被清洗', () => {
      const cleaned = stripControlCharsDeep({ 'k\ney': 'v' });
      expect(Object.keys(cleaned)).toEqual(['k ey']);
    });

    test('非对象值原样返回', () => {
      expect(stripControlCharsDeep(5)).toBe(5);
      expect(stripControlCharsDeep(null)).toBeNull();
    });
  });

  describe('sanitizeSpreadsheetCell', () => {
    test('危险前缀加单引号防公式注入', () => {
      expect(sanitizeSpreadsheetCell('=1+1')).toBe("'=1+1");
      expect(sanitizeSpreadsheetCell('+cmd')).toBe("'+cmd");
      expect(sanitizeSpreadsheetCell('-2')).toBe("'-2");
      expect(sanitizeSpreadsheetCell('@SUM(A1)')).toBe("'@SUM(A1)");
      expect(sanitizeSpreadsheetCell('\tx')).toBe("'\tx");
    });

    test('普通文本与非字符串不受影响', () => {
      expect(sanitizeSpreadsheetCell('正常设备名')).toBe('正常设备名');
      expect(sanitizeSpreadsheetCell('')).toBe('');
      expect(sanitizeSpreadsheetCell(100)).toBe(100);
      expect(sanitizeSpreadsheetCell(null)).toBeNull();
    });
  });

  describe('parseDateBoundary', () => {
    test('date-only 起始边界为本地当天零点', () => {
      expect(parseDateBoundary('2026-08-21', 'start')).toEqual(new Date(2026, 7, 21, 0, 0, 0, 0));
    });

    test('date-only 结束边界为本地当天 23:59:59.999', () => {
      expect(parseDateBoundary('2026-08-21', 'end')).toEqual(
        new Date(2026, 7, 21, 23, 59, 59, 999)
      );
    });

    test('回归：date-only 不走 new Date() 的 UTC 零点解析', () => {
      // new Date('2026-08-21') 在 GMT+8 是当天 08:00，会漏掉 00:00~08:00 的数据；
      // 手工构造本地时间后与 new Date(str) 的差值应为本地时区偏移而非恰好相等
      const parsed = parseDateBoundary('2026-08-21', 'start');
      const utcParsed = new Date('2026-08-21');
      const offsetMs = new Date(2026, 7, 21).getTimezoneOffset() * 60000;
      expect(parsed.getTime()).toBe(utcParsed.getTime() + offsetMs);
    });

    test('完整时间串透传给 new Date()', () => {
      const iso = '2026-08-21T10:30:00.000Z';
      expect(parseDateBoundary(iso, 'start').getTime()).toBe(new Date(iso).getTime());
      expect(parseDateBoundary(iso, 'end').getTime()).toBe(new Date(iso).getTime());
    });

    test('跨年与月末日期构造正确', () => {
      expect(parseDateBoundary('2026-12-31', 'end')).toEqual(
        new Date(2026, 11, 31, 23, 59, 59, 999)
      );
      expect(parseDateBoundary('2026-02-28', 'start')).toEqual(new Date(2026, 1, 28, 0, 0, 0, 0));
    });
  });

  describe('buildDateRangeFilter', () => {
    test('双边界：返回 {$gte,$lte} 且口径与 parseDateBoundary 一致', () => {
      const filter = buildDateRangeFilter('2026-08-01', '2026-08-31');
      expect(filter).toEqual({
        $gte: new Date(2026, 7, 1, 0, 0, 0, 0),
        $lte: new Date(2026, 7, 31, 23, 59, 59, 999),
      });
    });

    test('仅起始：只含 $gte', () => {
      expect(buildDateRangeFilter('2026-08-01', undefined)).toEqual({
        $gte: new Date(2026, 7, 1, 0, 0, 0, 0),
      });
    });

    test('仅结束：只含 $lte', () => {
      expect(buildDateRangeFilter(undefined, '2026-08-31')).toEqual({
        $lte: new Date(2026, 7, 31, 23, 59, 59, 999),
      });
    });

    test('双空：返回空对象（不产生空 $gte/$lte 键）', () => {
      expect(buildDateRangeFilter(undefined, undefined)).toEqual({});
      expect(buildDateRangeFilter('', '')).toEqual({});
    });
  });
});
