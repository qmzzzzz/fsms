/**
 * 异地备份前置判据（P1-4）单测：只测纯函数，不触文件系统/网络。
 */
'use strict';

const { checkBackupOffsite } = require('../../../scripts/deployPolicy');

describe('deployPolicy.checkBackupOffsite', () => {
  test('生产（NODE_ENV=production）缺 CMD/DIR ⇒ 拒绝发布', () => {
    const r = checkBackupOffsite({ NODE_ENV: 'production' });
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]).toContain('BACKUP_OFFSITE_CMD 或 BACKUP_OFFSITE_DIR');
  });

  test('显式 DEPLOY_ENFORCE_OFFSITE=true 同样拒绝（预发按生产口径）', () => {
    expect(checkBackupOffsite({ DEPLOY_ENFORCE_OFFSITE: 'true' }).errors).toHaveLength(1);
  });

  test('非生产且未显式强制：不误伤本地演练（errors/warnings 都为空）', () => {
    expect(checkBackupOffsite({})).toEqual({ errors: [], warnings: [] });
  });

  test('DIR 形态放行；CMD 形态放行', () => {
    expect(
      checkBackupOffsite({ NODE_ENV: 'production', BACKUP_OFFSITE_DIR: '/mnt/offsite' })
    ).toEqual({ errors: [], warnings: [] });
    expect(
      checkBackupOffsite({ NODE_ENV: 'production', BACKUP_OFFSITE_CMD: 'rclone copy' })
    ).toEqual({ errors: [], warnings: [] });
  });

  test('CMD 只含空白 ⇒ 生产直接拒绝（与备份脚本的失败口径一致）', () => {
    const r = checkBackupOffsite({ NODE_ENV: 'production', BACKUP_OFFSITE_CMD: '   ' });
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]).toContain('只含空白');
  });

  test('两者同时配置 ⇒ 告警（脚本 CMD 优先，避免配置了 DIR 以为会生效）', () => {
    const r = checkBackupOffsite({
      NODE_ENV: 'production',
      BACKUP_OFFSITE_CMD: 'rclone copy',
      BACKUP_OFFSITE_DIR: '/mnt/offsite',
    });
    expect(r.errors).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]).toContain('优先执行 CMD');
  });
});
