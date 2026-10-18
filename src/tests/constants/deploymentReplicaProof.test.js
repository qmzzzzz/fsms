/**
 * F-12（审计报告 2026-10-16）：K8s Deployment 多副本不能可靠触发多实例检测
 *
 * 缺陷本体：Deployment 的 `replicas: 3` **不会**自动注入任何环境变量，Pod 名
 * （`<name>-<rsHash>-<5位随机>`）也不带 StatefulSet 那样的序号。于是
 * detectMultiProcess 的六条判据在「纯 K8s 多副本」这个最常见的生产形态下
 * **全部落空**，旧实现只置 `k8sPodLike: true` 就结束，启动期连一条 warn 都没有——
 * 而审计哈希链分叉、限流配额放大正是这种拓扑下最先发生的事。
 *
 * 本次补的是**第三档**语义：`unproven`（在集群内但无法自证单副本）。
 * 它不是"检测到多副本"，所以刻意不进 `suspected`（那会打 error 级日志，
 * 把真信号稀释成每天一次的假警报）；但它也不能再是 debug 级静默放行。
 *
 * 同时新增部署期声明变量 `RUNTIME_INSTANCE_COUNT`：
 *   - =1 ⇒ 已声明单副本，提示消失
 *   - >1 ⇒ 与 INSTANCE_COUNT 同等对待，进 suspected
 *   - 非法/缺失 ⇒ 视为**未声明**（不得静默当作 1）
 *
 * 为什么不能复用 INSTANCE_COUNT 当"已声明单副本"的证明：`.env.example` 里
 * `INSTANCE_COUNT=1` 是随模板复制进 ConfigMap 的**默认值**，拿它当证明等于让
 * 所有按模板部署的集群自动闭嘴（见下方「默认值不是声明」用例）。
 */

const TOPOLOGY_ENV = [
  'INSTANCE_COUNT',
  'REPLICAS',
  'WEB_CONCURRENCY',
  'CLUSTER_WORKERS',
  'NODE_APP_INSTANCE',
  'instances',
  'KUBERNETES_SERVICE_HOST',
  'RUNTIME_INSTANCE_COUNT',
];

const DEPLOYMENT_HOST = 'fsms-api-7d9f8c7b6-23459'; // Deployment 形态（末段恰为 5 位数字）
const STATEFULSET_FIRST = 'fsms-api-0';

describe('F-12 无法自证单副本（unproven 档）', () => {
  const saved = {};
  beforeEach(() => {
    for (const k of TOPOLOGY_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    jest.resetModules();
  });
  afterEach(() => {
    for (const k of TOPOLOGY_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    jest.resetModules();
  });

  const load = () => require('../../constants/runtime');

  test('缺陷用例：集群内 + Deployment 形态 + 未声明副本数 ⇒ suspected=false 但 unproven=true', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    const r = load().detectMultiProcess({ hostname: DEPLOYMENT_HOST });

    // 旧实现到 k8sPodLike 就结束了 —— 这一行是缺陷本体的断言
    expect(r.k8sPodLike).toBe(true);
    expect(r.suspected).toBe(false); // 不得升级成 error 级假警报
    expect(r.unproven).toBe(true); // 但也不得静默放行
    expect(r.unprovenReason).toContain('RUNTIME_INSTANCE_COUNT');
    expect(r.unprovenReason).toContain('无法自证单副本');
  });

  test('反向闸：声明 RUNTIME_INSTANCE_COUNT=1 后提示消失（否则 unproven 只是恒真噪声）', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    process.env.RUNTIME_INSTANCE_COUNT = '1';
    const r = load().detectMultiProcess({ hostname: DEPLOYMENT_HOST });
    expect(r.suspected).toBe(false);
    expect(r.unproven).toBe(false);
    expect(r.unprovenReason).toBeNull();
  });

  test('RUNTIME_INSTANCE_COUNT>1 ⇒ 进 suspected，且理由写明是部署声明', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    process.env.RUNTIME_INSTANCE_COUNT = '3';
    const r = load().detectMultiProcess({ hostname: DEPLOYMENT_HOST });
    expect(r.suspected).toBe(true);
    expect(r.reasons.join(' ')).toContain('RUNTIME_INSTANCE_COUNT=3');
    // 已有强判据时不再重复提示"无法自证"
    expect(r.unproven).toBe(false);
  });

  test.each([['abc'], ['0'], ['-2'], ['1.5'], ['']])(
    '非法声明 %p 视为未声明（不得静默当作 1）',
    (raw) => {
      process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
      process.env.RUNTIME_INSTANCE_COUNT = raw;
      const { detectMultiProcess, readDeclaredInstanceCount } = load();
      expect(readDeclaredInstanceCount()).toBeNull();
      const r = detectMultiProcess({ hostname: DEPLOYMENT_HOST });
      expect(r.suspected).toBe(false);
      expect(r.unproven).toBe(true);
    }
  );

  test('默认值不是声明：INSTANCE_COUNT=1（.env.example 的默认值）不能证明单副本', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    process.env.INSTANCE_COUNT = '1'; // 模板默认值，随 ConfigMap 一起进容器
    const r = load().detectMultiProcess({ hostname: DEPLOYMENT_HOST });
    expect(r.suspected).toBe(false);
    expect(r.unproven).toBe(true);
  });

  test('StatefulSet 首副本（序号 0）同样不能自证单副本', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    const r = load().detectMultiProcess({ hostname: STATEFULSET_FIRST });
    // 序号 0 只说明"这是首个副本"，同族是否还有 app-1/app-2 无从得知
    expect(r.suspected).toBe(false);
    expect(r.unproven).toBe(true);
  });

  test('StatefulSet 非首副本仍走 suspected（不回归成 unproven）', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    const r = load().detectMultiProcess({ hostname: 'fsms-api-2' });
    expect(r.suspected).toBe(true);
    expect(r.unproven).toBe(false);
    expect(r.reasons.join(' ')).toContain('StatefulSet');
  });

  test('集群外不误报：没有 KUBERNETES_SERVICE_HOST 时 unproven 恒 false', () => {
    // `runner-14` / `ip-10-0-1-23` 这类形状在集群外不得触发任何档位
    for (const host of [DEPLOYMENT_HOST, 'runner-14', 'ip-10-0-1-23', 'localhost']) {
      const r = load().detectMultiProcess({ hostname: host });
      expect(r.unproven).toBe(false);
      expect(r.suspected).toBe(false);
    }
  });
});

describe('F-12 启动期日志：unproven 走 warn、suspected 走 error', () => {
  const saved = {};
  beforeEach(() => {
    for (const k of TOPOLOGY_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    jest.resetModules();
  });
  afterEach(() => {
    for (const k of TOPOLOGY_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    jest.resetModules();
  });

  const loadWithLogger = () => {
    jest.resetModules();
    const logger = require('../../utils/logger');
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const error = jest.spyOn(logger, 'error').mockImplementation(() => {});
    const runtime = require('../../constants/runtime');
    return { runtime, warn, error };
  };

  test('unproven：warn 一条、error 零条，消息含声明指引与失效清单', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    const { runtime, warn, error } = loadWithLogger();

    expect(() => runtime.assertSingleProcessAssumptions()).not.toThrow();
    expect(error).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);

    const msg = warn.mock.calls[0][0];
    expect(msg).toContain('无法证明本进程是唯一实例');
    expect(msg).toContain('RUNTIME_INSTANCE_COUNT');
    // 清单必须仍然列出（"若实际存在多个副本，这些会降级"），否则提示没有信息量
    expect(msg).toContain('auditChain');
    expect(msg).toContain('services/auditBuffer.js');
    warn.mockRestore();
    error.mockRestore();
  });

  test('声明 RUNTIME_INSTANCE_COUNT=1 后既不 warn 也不 error', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    process.env.RUNTIME_INSTANCE_COUNT = '1';
    const { runtime, warn, error } = loadWithLogger();

    runtime.assertSingleProcessAssumptions();
    expect(warn).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
    warn.mockRestore();
    error.mockRestore();
  });

  test('suspected 仍是 error（不得因为新增 warn 档把真信号降级）', () => {
    process.env.WEB_CONCURRENCY = '4';
    const { runtime, warn, error } = loadWithLogger();

    runtime.assertSingleProcessAssumptions();
    expect(error).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
    expect(error.mock.calls[0][0]).toContain('WEB_CONCURRENCY=4');
    warn.mockRestore();
    error.mockRestore();
  });

  test('返回结构自带 unproven，调用方不必再自己推断', () => {
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    const { runtime, warn, error } = loadWithLogger();
    const r = runtime.assertSingleProcessAssumptions();
    expect(r).toMatchObject({ suspected: false, unproven: true });
    warn.mockRestore();
    error.mockRestore();
  });
});
