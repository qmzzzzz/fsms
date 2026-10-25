/**
 * 默认管理员初始口令文件：一次性凭据语义（首次登录/改密后必须消失）。
 *
 * 原实现只在创建时收紧权限，从不删除：该文件含明文管理员口令，却会在磁盘上
 * 长期留存。本用例锁定删除范围（只有默认超管）、删除结果与失败告警。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const initialPasswordFile = require('../../services/initialPasswordFile');
const logger = require('../../utils/logger');
const metrics = require('../../utils/metrics');

describe('initialPasswordFile：一次性凭据生命周期', () => {
  let dir;
  let oldCwd;
  let oldName;

  const seed = () => {
    const file = initialPasswordFile.filePath();
    fs.writeFileSync(file, 'username: root_admin\npassword: secret\n');
    return file;
  };

  beforeEach(() => {
    oldCwd = process.cwd();
    oldName = process.env.SUPER_ADMIN_USERNAME;
    process.env.SUPER_ADMIN_USERNAME = 'root_admin';
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'initpwd-lifecycle-'));
    process.chdir(dir);
    jest.spyOn(logger, 'info').mockImplementation(() => {});
    jest.spyOn(logger, 'error').mockImplementation(() => {});
    jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
    process.chdir(oldCwd);
    if (oldName === undefined) delete process.env.SUPER_ADMIN_USERNAME;
    else process.env.SUPER_ADMIN_USERNAME = oldName;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('默认超管登录/改密后删除文件', () => {
    const file = seed();
    expect(initialPasswordFile.consume('Root_Admin', '首次登录')).toBe(true);
    expect(fs.existsSync(file)).toBe(false);
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('首次登录'));
  });

  test('普通用户不得删除（注册/普通登录共用同一钩子）', () => {
    const file = seed();
    expect(initialPasswordFile.consume('someone_else', '首次登录')).toBe(false);
    expect(fs.existsSync(file)).toBe(true);
  });

  test('文件不存在时静默返回 false（不告警、不抛）', () => {
    expect(initialPasswordFile.consume('root_admin', '修改密码')).toBe(false);
    expect(logger.error).not.toHaveBeenCalled();
    expect(metrics.incSecurityAlert).not.toHaveBeenCalled();
  });

  test('删除失败：error + high 告警，且登录流程不被异常打断', () => {
    const file = seed();
    jest.spyOn(fs, 'unlinkSync').mockImplementation(() => {
      throw new Error('EPERM: operation not permitted');
    });

    expect(() => initialPasswordFile.consume('root_admin', '首次登录')).not.toThrow();
    expect(initialPasswordFile.consume('root_admin', '首次登录')).toBe(false);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('请立即手动删除'));
    expect(metrics.incSecurityAlert).toHaveBeenCalledWith(
      'admin_initial_password_file_delete_failed',
      'high'
    );
    expect(fs.existsSync(file)).toBe(true);
  });
});
