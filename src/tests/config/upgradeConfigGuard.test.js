'use strict';

/**
 * 热升级队列配置的「错配必须出声」（审计 2026-11-14）
 *
 * config/upgrade 的 toPositiveInt 曾对越界/非法配置**静默**回落默认值：运维把
 * UPGRADE_REQUEST_TTL_SECONDS 写错（低于 60s 下界、非数字），服务照常按默认跑，
 * 错配只能在行为不对时被人肉发现——与仓内「错配必须出声」口径（envNumber 的
 * onInvalid、auditFlushBatchLimit 的告警回落）相悖。
 *
 * 口径与 envNumber 一致：未配置/空白 = 配置缺省是正常状态，静默用默认、零告警；
 * 已配置但非法/越界 = 错配，告警（点名字、点名原值、点名回退值）后回落。
 */

const ENV_KEYS = [
  'UPGRADE_ENABLED',
  'UPGRADE_QUEUE_DIR',
  'UPGRADE_AGENT_STALE_SECONDS',
  'UPGRADE_REQUEST_TTL_SECONDS',
  'UPGRADE_HISTORY_LIMIT',
  'HOT_UPGRADE_REGISTRY_ALLOWLIST',
];

describe('config/upgrade toPositiveInt 错配出声', () => {
  const saved = {};
  beforeAll(() => {
    for (const key of ENV_KEYS) {
      saved[key] = process.env[key];
      delete process.env[key];
    }
  });
  afterAll(() => {
    for (const key of ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  });

  /** 每例重新求值配置（模块加载期读 env），并捕获加载期发出的 warn */
  const loadConfig = () => {
    jest.resetModules();
    const logger = require('../../utils/logger');
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const config = require('../../config/upgrade');
    return { config, warnSpy };
  };

  test('未配置/空白：静默用默认，零告警（配置缺省是正常状态）', () => {
    process.env.UPGRADE_AGENT_STALE_SECONDS = '   ';
    delete process.env.UPGRADE_REQUEST_TTL_SECONDS;
    const { config, warnSpy } = loadConfig();
    expect(config.agentStaleMs).toBe(120 * 1000);
    expect(config.requestTtlMs).toBe(1800 * 1000);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  test('已配置但越界/非法：告警点名字与原值，并回落默认', () => {
    process.env.UPGRADE_AGENT_STALE_SECONDS = '10'; // 低于下界 30
    process.env.UPGRADE_REQUEST_TTL_SECONDS = 'abc';
    const { config, warnSpy } = loadConfig();
    expect(config.agentStaleMs).toBe(120 * 1000);
    expect(config.requestTtlMs).toBe(1800 * 1000);
    const messages = warnSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(messages).toContain('UPGRADE_AGENT_STALE_SECONDS=10 非法');
    expect(messages).toContain('UPGRADE_REQUEST_TTL_SECONDS=abc 非法');
    expect(messages).toContain('已回退默认 120');
    expect(messages).toContain('已回退默认 1800');
  });

  test('合法值原样生效且不告警', () => {
    process.env.UPGRADE_AGENT_STALE_SECONDS = '600';
    process.env.UPGRADE_REQUEST_TTL_SECONDS = '3600';
    process.env.UPGRADE_HISTORY_LIMIT = '25';
    const { config, warnSpy } = loadConfig();
    expect(config.agentStaleMs).toBe(600 * 1000);
    expect(config.requestTtlMs).toBe(3600 * 1000);
    expect(config.historyLimit).toBe(25);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
