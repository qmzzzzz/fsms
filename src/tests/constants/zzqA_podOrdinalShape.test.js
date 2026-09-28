/**
 * parsePodOrdinal 的形态判定顺序契约（2026-09-19 实测缺陷）
 *
 * 缺陷：K8s Pod 名的 5 位随机后缀取自元音回避字母表
 * `bcdfghjklmnpqrstvwxz23456789`（含数字），而原实现先跑「末段纯数字 = StatefulSet
 * 序号」再跑 Deployment 形态。于是单副本 Deployment 的 `api-7d9f8c7b6-23459`
 * 被判成 ordinal=23459 的非首副本 ⇒ strong ⇒ assertSingleProcessAssumptions()
 * 每次启动打一条 error 级「检测到多进程/多实例运行迹象」并列出失效清单。
 * 假警报的代价不是日志难看，而是训练运维忽略这条真信号（多副本会让审计链分叉）。
 *
 * 用例同时钉住反方向：不得靠「给序号设上限」或干脆关掉判据来消警报——
 * 合法的大序号 StatefulSet 与真·非首副本必须仍然报 strong。
 */

const { parsePodOrdinal, detectMultiProcess } = require('../../constants/runtime');

// detectMultiProcess 还会读这些环境变量；必须显式清空，否则用例结论取决于
// 跑它的是哪个套件/进程（本项目最常见的假绿形态就是"前提写在别的用例里"）。
const TOPOLOGY_ENV = [
  'INSTANCE_COUNT',
  'REPLICAS',
  'WEB_CONCURRENCY',
  'CLUSTER_WORKERS',
  'NODE_APP_INSTANCE',
  'instances',
  // strong 判据现在要求"确实在集群里"，所以这条必须显式受控，
  // 否则用例结论取决于跑它的那个 CI runner/机器有没有这个变量。
  'KUBERNETES_SERVICE_HOST',
];

describe('parsePodOrdinal：Deployment 形态必须先于纯数字序号判定', () => {
  const saved = {};
  beforeEach(() => {
    for (const k of TOPOLOGY_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    // 默认"在集群内"，让 StatefulSet 序号档保持可测；
    // 集群外的假警报由专门的用例覆盖（不靠默认环境碰运气）。
    process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
  });
  afterEach(() => {
    for (const k of TOPOLOGY_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  test('缺陷用例：末段恰为 5 位纯数字的 Deployment Pod 名不得算作多副本', () => {
    // 实测原实现返回 {podLike:true, ordinal:23459, strong:true}
    expect(parsePodOrdinal('api-7d9f8c7b6-23459')).toEqual({
      podLike: true,
      ordinal: null,
      strong: false,
    });
    // 该后缀全部落在 K8s 真实字母表的数字子集里，逐个都必须为弱信号
    for (const suffix of ['22222', '23459', '99999', '87654']) {
      expect(parsePodOrdinal(`fire-safety-api-5d9f8c7b6-${suffix}`).strong).toBe(false);
    }
  });

  test('反向闸：真·StatefulSet 非首副本仍然报 strong（不得用"上限"或关掉判据消警报）', () => {
    expect(parsePodOrdinal('app-1')).toMatchObject({ podLike: true, ordinal: 1, strong: true });
    expect(parsePodOrdinal('fsms-prod-3')).toMatchObject({ ordinal: 3, strong: true });
    // 6 位数字末段不属于 Deployment 形态（后缀恒为 5 位），仍是合法大序号 StatefulSet。
    // 若有人用「ordinal 超过某个值就不算多副本」来绕过上面的假警报，这条会红。
    expect(parsePodOrdinal('app-123456')).toMatchObject({ ordinal: 123456, strong: true });
  });

  test('首副本与 Deployment 弱信号仍只置 podLike', () => {
    expect(parsePodOrdinal('app-0')).toEqual({ podLike: true, ordinal: 0, strong: false });
    expect(parsePodOrdinal('web-5f8g2h9j4-b7d9f')).toEqual({
      podLike: true,
      ordinal: null,
      strong: false,
    });
  });

  test('非编排器主机名不得置 podLike（防把本地机误报成 Pod）', () => {
    for (const h of ['localhost', 'LAPTOP-V29F6ASQ', 'build-agent-07.internal', '']) {
      expect(parsePodOrdinal(h).podLike).toBe(false);
    }
  });

  test('复核 实测的假警报：集群外"主机名以 -数字 结尾"一律不得报 strong', () => {
    // CI runner 编号与 EC2 私有 DNS 名都不是 StatefulSet Pod。修复前实测四者全部
    // strong:true + suspected:true ⇒ 单实例机器每次启动一条 error 级"检测到多实例"
    // + 整页失效清单（正是本模块开头警告的"假警报训练运维忽略真信号"）。
    for (const host of ['runner-14', 'ci-agent-3', 'host-2024', 'ip-10-0-1-23']) {
      delete process.env.KUBERNETES_SERVICE_HOST;
      const r = parsePodOrdinal(host);
      expect(r.podLike).toBe(true); // 形状线索保留（k8sPodLike 提示用）
      expect(r.strong).toBe(false);
      expect(detectMultiProcess({ hostname: host }).suspected).toBe(false);
      // 同一主机名一旦确实跑在集群里，序号重新算强信号
      // ——这一半是防止有人将来干脆写死 strong:false 来消警报。
      process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
      expect(parsePodOrdinal(host).strong).toBe(true);
    }
  });

  test('端到端：detectMultiProcess 对单副本 Deployment 主机名不得 suspected', () => {
    // error 级日志的实际触发条件在这里，只测纯函数不足以覆盖这条因果
    const singleReplicaDeployment = detectMultiProcess({ hostname: 'api-7d9f8c7b6-23459' });
    expect(singleReplicaDeployment.suspected).toBe(false);
    expect(singleReplicaDeployment.k8sPodLike).toBe(true);

    const realStatefulSetSecondReplica = detectMultiProcess({ hostname: 'app-1' });
    expect(realStatefulSetSecondReplica.suspected).toBe(true);
    expect(realStatefulSetSecondReplica.reasons.join(' ')).toContain('StatefulSet');
  });

  test('可证伪：若把 Deployment 判据删掉，缺陷用例必须立刻变红', () => {
    // 本模块没有可注入的"开关"，用形状等价的方式验证两条判据确实互斥：
    // 同一个主机名，去掉 rsHash 段后应立刻按 StatefulSet 序号解释。
    expect(parsePodOrdinal('api-7d9f8c7b6-23459').strong).toBe(false);
    expect(parsePodOrdinal('api-23459')).toMatchObject({ ordinal: 23459, strong: true });
  });
});
