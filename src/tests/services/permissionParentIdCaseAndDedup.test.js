/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（第 28 轮 · 2026-10-04）
 *
 * 被测对象：permissionService.batchCreatePermissions 的**父级存在性判定**
 * 守护的不变式：C2 缺陷类（请求侧 id 清单与驱动侧 id 清单必须同一口径）在
 *   "构造 $in 清单"与"逐项 has() 比对"两条臂上同时成立
 * 可证伪性：文末变异台账（模式名 + 预测 + 实测红腿编号）
 * 不碰数据库：模型层整体替身，$in 的 cast 语义由替身复刻
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 为什么单独一把闸，而不并入 requestedIdListDeduped.test.js：
 * 那把闸钉的是控制器把请求数组交给服务层**之前**的归一，而这里的比较发生在服务层**内部**
 * ——同一个缺陷类换了一层，原闸一条腿都覆盖不到（第 6 族：按调用面切分覆盖，漏的正是切缝）。
 *
 * 缺陷形状（修复前，逐行核实）：
 *   `parentIds = [...new Set(map(String))]` 只去重不转小写；
 *   `validParentIds` 由 `String(item._id)` 构成，而驱动恒返回小写 hex（bson toHexString）；
 *   逐项 `validParentIds.has(String(parent))` 于是拿**原始大写写法**去比小写集合。
 *   路由侧 `body('permissions.*.parent').isMongoId()` 挡不住大写（isMongoId 委托十六进制
 *   判定，大小写 alike），`$in` 又按 12 字节 cast ⇒ 文档命中了、has() 却没命中 ⇒
 *   **真实存在的父级被判成「父级权限不存在」**，该项静默进 skipped：不 400、不报错、
 *   响应照样 success。批量导入的后果不是文案，是"少建了几条权限且无人知晓"。
 */

const mockIds = {
  parentA: '0000000000000000000000a1',
  parentB: '0000000000000000000000a2',
  missing: '0000000000000000000000ff',
};

/** 世界状态：权限表按 cast 后的 12 字节（等价于小写 hex）建键，与 Mongo 一致 */
const mockStore = { perms: {}, inserted: [] };

const castLookup = (ids) => [...new Set((ids || []).map((id) => String(id).toLowerCase()))];

jest.mock('../../models/Permission', () => {
  const chain = (docs) => ({
    select: () => ({ lean: async () => docs }),
  });
  return {
    find: jest.fn((filter) => {
      // 复刻驱动的两条查询：按 code 查已存在、按 _id($in) 查父级存在性。
      // $in 的语义是"cast 成 ObjectId 后去重命中"，不是字符串相等：
      // `67ED…` 与 `67ed…` 是同一个文档，只回一份。
      if (filter && filter.code && filter.code.$in) {
        const hit = castLookup(filter.code.$in)
          .map((code) => mockStore.perms[code])
          .filter(Boolean);
        return chain(hit.map((doc) => ({ code: doc.code })));
      }
      if (filter && filter._id && filter._id.$in) {
        const hit = castLookup(filter._id.$in)
          .map((id) => mockStore.perms[id])
          .filter(Boolean);
        return chain(hit.map((doc) => ({ _id: doc._id })));
      }
      return chain([]);
    }),
    insertMany: jest.fn(async (docs) => {
      // 把"真正会被写入的那一份"存住：断言写的是 validDocs 而不是别的什么
      mockStore.inserted.push(...docs);
      return docs.map((doc, i) => ({ ...doc, _id: `new${i}` }));
    }),
  };
});

jest.mock('../../models/Role', () => ({
  countDocuments: jest.fn(async () => 0),
}));

const permissionService = require('../../services/permissionService');

const seed = () => {
  mockStore.perms = {
    [mockIds.parentA]: { _id: mockIds.parentA, code: 'facility:read' },
    [mockIds.parentB]: { _id: mockIds.parentB, code: 'facility:update' },
  };
};
seed();

const item = (code, parent) => ({
  name: `权限 ${code}`,
  code,
  type: 'action',
  module: 'facility',
  ...(parent === undefined ? {} : { parent }),
});

/** 一次批量创建：返回 {result, skippedByCode, inserted}；每次调用前清空写入捕获 */
const batch = async (items) => {
  mockStore.inserted = [];
  const result = await permissionService.batchCreatePermissions(items);
  const skippedByCode = {};
  (result.skipped || []).forEach((s) => {
    skippedByCode[s.code] = s.reason;
  });
  return { result, skippedByCode, inserted: mockStore.inserted };
};

describe('批量创建的父级存在性判定', () => {
  test('替身前提：按大写父级 id 查 $in 也要命中，两种写法只回一份文档', async () => {
    const Permission = require('../../models/Permission');
    const upper = mockIds.parentA.toUpperCase();
    const onlyUpper = await Permission.find({ _id: { $in: [upper] } })
      .select('_id')
      .lean();
    // 数量与内容一起断：只断"数量 1"会放过"命中了别的文档"和丢弃型替身两种退化
    expect(onlyUpper.length).toBe(1);
    expect(String(onlyUpper[0]._id)).toBe(mockIds.parentA);
    const both = await Permission.find({ _id: { $in: [upper, mockIds.parentA] } })
      .select('_id')
      .lean();
    expect(both.length).toBe(1);
  });

  test('大写写法的既有父级：不得被判成「父级权限不存在」而静默跳过', async () => {
    const { skippedByCode, inserted } = await batch([
      item('facility:sub1', mockIds.parentA.toUpperCase()),
    ]);
    expect(skippedByCode['facility:sub1']).toBeUndefined();
    expect(inserted.length).toBe(1);
    expect(inserted[0].code).toBe('facility:sub1');
  });

  test('同一父级的大小写两种写法（不同子项）：两条都得建', async () => {
    const { skippedByCode, inserted } = await batch([
      item('facility:sub1', mockIds.parentA),
      item('facility:sub2', mockIds.parentA.toUpperCase()),
    ]);
    expect(inserted.length).toBe(2);
    expect(skippedByCode['facility:sub2']).toBeUndefined();
  });

  test('归一不得吞掉真实缺失：不存在的父级（大写写法）仍然 skipped', async () => {
    const { skippedByCode, inserted } = await batch([
      item('facility:sub1', mockIds.missing.toUpperCase()),
    ]);
    expect(inserted.length).toBe(0);
    expect(skippedByCode['facility:sub1']).toContain('父级权限不存在');
  });

  test('真缺失与真实存在混在一个批次：只跳那一条，其余照建', async () => {
    const { skippedByCode, inserted } = await batch([
      item('facility:ok', mockIds.parentB),
      item('facility:bad', mockIds.missing),
      item('facility:okUpper', mockIds.parentB.toUpperCase()),
    ]);
    expect(inserted.map((d) => d.code).sort()).toEqual(['facility:ok', 'facility:okUpper']);
    expect(skippedByCode['facility:bad']).toContain('父级权限不存在');
  });

  test('不传父级（顶层权限）不受影响：归一入口不得把 undefined 变成引用', async () => {
    const { skippedByCode, inserted } = await batch([item('facility:top')]);
    expect(inserted.length).toBe(1);
    expect(skippedByCode['facility:top']).toBeUndefined();
  });
});

/* ============================== 变异台账（先写预测，再实测）==============================
 * 施加方式：node tools/ledger.js src/services/permissionService.js \
 *   src/tests/services/permissionParentIdCaseAndDedup.test.js <模式>=<预测> …
 * 腿编号按声明顺序：#1 替身前提｜#2 大写父级放行｜#3 同一父级两种写法都建
 *   #4 真缺失仍拒｜#5 混合批次｜#6 顶层权限
 *
 * 预测（写于实测之前）：
 *   parent-compare-raw（has(canonicalIdString(parent)) 退回 has(String(parent))）→ 红:#2,#3,#5
 *   parent-norm-dropped（parentIds 退回手写 new Set(map(String))，不转小写）    → 绿（等价变异）
 *   perm-stub-case-sensitive（仪器变异：替身查表不再转小写）                    → 红:#1
 *
 * 为什么"清单归一"这一条预测是**绿**而不是红（这是本站点与前七个站点的结构差异）：
 * 前七处的形状是「归一后的长度 vs 文档数」比较，清单归一承重；这里没有长度比较，
 * `validParentIds` 是从**返回的文档**构造的集合，而 `$in` 本来就把大小写两种写法 cast 成
 * 同一个 12 字节——所以去掉清单归一不改变任何可观察行为，是一条真·等价变异。
 * 记下它而不是补一条假腿去"抓"它：补出来的腿只能抓替身，抓不到生产。
 * 反过来这也说明本缺陷**全部**住在单值比较那一臂里，因此修复要的是 canonicalIdString
 * （单值入口）而不是又一次 uniqueIdStrings——这正是前一轮普查按"数组清单"扫描时漏掉它的原因。
 *
 * 实测（2026-10-04）：见交付台账；与预测不一致的条目原样保留。
 */
