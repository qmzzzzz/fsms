/**
 * 超级管理员唯一性与不可变更约束单测
 */

const {
  SUPER_ADMIN_ROLE_CODE,
  getSuperAdminUsername,
  isSuperAdminRole,
  checkSuperAdminMembership,
} = require('../../utils/superAdmin');

const superRole = { code: 'SUPER_ADMIN', isBuiltIn: true };
const guestRole = { code: 'GUEST', isBuiltIn: true };
const secRole = { code: 'SECURITY_ADMIN', isBuiltIn: true };

describe('superAdmin 工具', () => {
  describe('getSuperAdminUsername', () => {
    const original = process.env.SUPER_ADMIN_USERNAME;
    afterEach(() => {
      if (original === undefined) delete process.env.SUPER_ADMIN_USERNAME;
      else process.env.SUPER_ADMIN_USERNAME = original;
    });

    test('未配置环境变量时固定为 admin', () => {
      delete process.env.SUPER_ADMIN_USERNAME;
      expect(getSuperAdminUsername()).toBe('admin');
    });

    test('环境变量可覆盖并自动去除首尾空白', () => {
      process.env.SUPER_ADMIN_USERNAME = '  root_admin  ';
      expect(getSuperAdminUsername()).toBe('root_admin');
    });

    test('环境变量为空白串时回退 admin', () => {
      process.env.SUPER_ADMIN_USERNAME = '   ';
      expect(getSuperAdminUsername()).toBe('admin');
    });
  });

  describe('isSuperAdminRole', () => {
    test('code 与 isBuiltIn 同时满足才判定为超管角色', () => {
      expect(isSuperAdminRole(superRole)).toBe(true);
    });

    test('仅 code 匹配但非内置角色不算超管（防克隆角色冒用）', () => {
      expect(isSuperAdminRole({ code: 'SUPER_ADMIN', isBuiltIn: false })).toBe(false);
      expect(isSuperAdminRole({ code: 'SUPER_ADMIN' })).toBe(false);
    });

    test('其他内置角色不算超管', () => {
      expect(isSuperAdminRole(guestRole)).toBe(false);
      expect(isSuperAdminRole(secRole)).toBe(false);
    });

    test('空值输入安全返回 false', () => {
      expect(isSuperAdminRole(null)).toBe(false);
      expect(isSuperAdminRole(undefined)).toBe(false);
      expect(isSuperAdminRole({})).toBe(false);
    });

    test('导出的角色编码常量与判定一致', () => {
      expect(isSuperAdminRole({ code: SUPER_ADMIN_ROLE_CODE, isBuiltIn: true })).toBe(true);
    });
  });

  describe('checkSuperAdminMembership', () => {
    test('剥离超管角色被拒（含操作者本人，无 isSelf 例外）', () => {
      const err = checkSuperAdminMembership([superRole], [guestRole]);
      expect(err).toBeTruthy();
      expect(err.code).toBe('SUPER_ADMIN_ROLE_NOT_DETACHABLE');
      expect(err.message).toContain('不可被剥离');
    });

    test('授予超管角色被拒（保唯一性）', () => {
      const err = checkSuperAdminMembership([guestRole], [guestRole, superRole]);
      expect(err).toBeTruthy();
      expect(err.code).toBe('SUPER_ADMIN_ROLE_NOT_GRANTABLE');
      expect(err.message).toContain('不可被授予');
    });

    test('保留超管角色、仅增删其他角色时放行', () => {
      expect(checkSuperAdminMembership([superRole], [superRole, secRole])).toBeNull();
      expect(checkSuperAdminMembership([superRole, secRole], [superRole])).toBeNull();
    });

    test('全程不涉及超管的变更放行', () => {
      expect(checkSuperAdminMembership([guestRole], [secRole])).toBeNull();
    });

    test('空角色集不误判', () => {
      expect(checkSuperAdminMembership([], [])).toBeNull();
      expect(checkSuperAdminMembership(undefined, undefined)).toBeNull();
    });

    test('非内置的同名 code 角色不触发拦截（与 isSuperAdminRole 口径一致）', () => {
      const fake = { code: 'SUPER_ADMIN', isBuiltIn: false };
      expect(checkSuperAdminMembership([fake], [guestRole])).toBeNull();
    });
  });
});
