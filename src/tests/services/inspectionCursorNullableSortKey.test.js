/**
 * 排序键可为空的列表：游标链条必须能被自己吃回去，且不得静默截断
 *
 * 缺陷本体（`planStartTime` 在 `models/Inspection` 里是 `type: Date` 无 required 无 default，
 * 而巡检列表正是按它倒序排）：
 *   ① 边界文档**没有**该键时，`encodeCursor({ v: undefined, ... })` 走的是
 *      `JSON.stringify` —— undefined 值会被**整键丢掉**，下发的游标解出来是 `{"id":"…"}`，
 *      没有 `v` ⇒ `decodeCursor` 抛 400「分页游标无效，请从第一页重新查询」。
 *      客户端照提示回到第一页，再翻到这里又是 400：**永久死循环**，服务端零日志。
 *      实测：`buildCursorResult([{_id},{_id}], 1, 'planStartTime').nextCursor`
 *            解回 `{"id":"6ab6c4685f7a989d757fae04"}`（无 v 键）。
 *   ② 边界文档的该键是 null（或该键缺失）时，游标能解开（`assertCursorValueShape` 允许 null），
 *      但 `valueType:'date'` 分支把它 `new Date(null)` ⇒ **1970-01-01**，
 *      条件退化成"找 1970 年之前的记录"。实测生成的查询：
 *        {"$or":[{"planStartTime":{"$lt":"1970-01-01T00:00:00.000Z"}},
 *                {"planStartTime":"1970-01-01T00:00:00.000Z","_id":{"$lt":"…"}}]}
 *      ⇒ 恒空页 + `hasMore:false`，用户看到"就这些了"，而实际后面还有整块空值记录。
 *      （`valueType:'number'` 同理，`Number(null) === 0`。）
 *   ③ 更根本的一条是本次实测出来的：**MongoDB 的范围比较不跨类型**。
 *      `{f:{$lt:<date>}}` 对 null 与缺失键都返回**空集**（`{$lte:null}`/`{f:null}` 才命中，
 *      且 `{f:null}` 同时命中"显式 null"与"根本没有这个键"）。倒序时空值块排在**尾部**，
 *      所以原实现在"最后一条有值记录"之后就直接 `hasMore:false` ——
 *      整块无日期记录在游标模式下**永远翻不到**。实测（mongod 6.0.14，5 条夹具：
 *      3 条有日期 + 1 条缺键 + 1 条显式 null，limit=1 逐页走完）：
 *        修复前 ⇒ 看到 3 条（有日期的那 3 条），空值块 0 条
 *        只修空值口径（`.sort()` 仍只排主键）⇒ 4 条：块内漂移仍会吞掉缺键那条
 *        再补上 `_id` 次级排序键 ⇒ 5 条全到（本文件现在钉的就是这一格）
 *
 * 修法口径（本文件钉这四条）：
 *   · 编码器是线上格式的唯一出口：`v` 为 undefined 时落成 `null`（null 是"没有排序键"的
 *     忠实线上表示），四个 offset 模式直调 `encodeCursor` 的服务点一并被收口；
 *   · `v === null` 走**空值块**专用条件，绝不进日期/数字/字符串的类型转换；
 *   · 倒序 + 有值时，条件要并上 `{f:{$lte:null}}`，把排在尾部的空值块接进来；
 *   · 空值块条件必须真的能把块内其余文档查出来（用真库验，不靠读代码相信 `{f:null}` 语义）。
 *
 * 块内的先后顺序（本文件此前记为"不可依赖"的另一件事）现在已经可依赖：
 * 调用点的 `.sort()` 带上了 `_id` 次级键（与游标子句同向，见 `cursorPagination.js`
 * 文件头），排序成为全序。此前只排主键时实测同一份空值块
 * `find({}).sort({f:1})` 与 `find({}).sort({f:1}).limit(2)` 给出的块内顺序**不一样**
 * （计划相关），且升序翻页走完只有 `E → C → B → A` —— 缺键的 D 被块内漂移跳过。
 * 那两条弱断言（"至少被触及一次"、"长度 ≤ 5"）就是照当时的漂移写的 ⇒ 已收紧成
 * "5 条全到、各一次"，本文件同时是那次收紧的落点。
 */

const mongoose = require('mongoose');
const Inspection = require('../../models/Inspection');
// 服务里的 populate 指向这两个模型（devices / assignedTo / reviewedBy）。本文件直接
// require 服务而不经过 app 启动链路，模型不会被自动登记，缺一个就是 MissingSchemaError。
require('../../models/FireDevice');
require('../../models/User');
const InspectionService = require('../../services/InspectionService');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../../utils/cursorPagination');

const STAMP = Date.now().toString(36).toUpperCase();
const TAG = `ZZNULLE${STAMP}`; // 混合夹具：有值 + 缺键 + 显式 null
const TAG2 = `ZZNULLF${STAMP}`; // 全空值夹具（与 TAG 互不为子串，search 不会互相命中）
const SORT_FIELD = 'planStartTime';

const dated = (title, day) => ({
  title,
  inspectionType: 'daily',
  planStartTime: new Date(`2026-09-0${day}T00:00:00.000Z`),
});

describe('可空排序键的游标链条', () => {
  describe('纯函数层：编码器与条件构造', () => {
    test('前提：undefined 排序键经 JSON 编码会整键消失（这正是 400 的根因）', () => {
      expect(JSON.stringify({ v: undefined, id: 'x' })).toBe('{"id":"x"}');
      expect('v' in JSON.parse(JSON.stringify({ v: undefined, id: 'x' }))).toBe(false);
    });

    test('服务端自己下发的游标，服务端自己必须能解回去（缺键边界）', () => {
      const docs = [{ _id: new mongoose.Types.ObjectId() }, { _id: new mongoose.Types.ObjectId() }];
      const { nextCursor } = buildCursorResult(docs, 1, SORT_FIELD);
      expect(typeof nextCursor).toBe('string');
      let decoded;
      expect(() => {
        decoded = decodeCursor(nextCursor);
      }).not.toThrow();
      // 解回来的 v 必须是"空值"而不是"没有这一项"，且必须是 null（与 ② 的口径衔接）
      expect(decoded).toHaveProperty('v', null);
    });

    test('空值边界不得被静默压成 1970（date）或 0（number）', () => {
      const id = String(new mongoose.Types.ObjectId());
      for (const valueType of ['date', 'number']) {
        const query = applyCursorCondition(
          { status: 'pending' },
          { sortField: SORT_FIELD, sortDir: -1, cursor: { v: null, id }, valueType }
        );
        const text = JSON.stringify(query);
        expect(text).not.toMatch(/1970-01-01T00:00:00\.000Z/);
        expect(text).not.toMatch(/"planStartTime":0/);
        expect(text).not.toMatch(/"planStartTime":\{"\$lt":0\}/);
        // 基础过滤条件必须原样保留（不得把 $and 里的 baseQuery 弄丢）
        expect(text).toMatch(/"status":"pending"/);
      }
    });

    test('反向对照：正常日期边界的范围子句与平局子句逐字段不变', () => {
      const id = String(new mongoose.Types.ObjectId());
      const query = applyCursorCondition(
        {},
        {
          sortField: SORT_FIELD,
          sortDir: -1,
          cursor: { v: '2026-09-01T00:00:00.000Z', id },
          valueType: 'date',
        }
      );
      const clauses = query.$and[1].$or;
      expect(clauses.slice(0, 2)).toEqual([
        { [SORT_FIELD]: { $lt: new Date('2026-09-01T00:00:00.000Z') } },
        {
          [SORT_FIELD]: new Date('2026-09-01T00:00:00.000Z'),
          _id: { $lt: new mongoose.Types.ObjectId(id) },
        },
      ]);
    });

    test('倒序 + 有值：条件必须接得住排在尾部的空值块（否则整块永久不可达）', () => {
      const id = String(new mongoose.Types.ObjectId());
      const opts = (sortDir) => ({
        sortField: SORT_FIELD,
        sortDir,
        cursor: { v: '2026-09-01T00:00:00.000Z', id },
        valueType: 'date',
      });
      const desc = applyCursorCondition({}, opts(-1)).$and[1].$or;
      const asc = applyCursorCondition({}, opts(1)).$and[1].$or;
      // 倒序：块在尾部 ⇒ 要接进来
      expect(desc).toContainEqual({ [SORT_FIELD]: { $lte: null } });
      // 升序：块在头部，走到有值区间时块已整体在过去 ⇒ 并进来看就会重复下发
      expect(asc).not.toContainEqual({ [SORT_FIELD]: { $lte: null } });
      expect(asc).toContainEqual({ [SORT_FIELD]: { $gt: new Date('2026-09-01T00:00:00.000Z') } });
    });

    test('空值块条件本身也要分方向：升序接住块外有值文档，倒序不得回头重复下发', () => {
      const id = String(new mongoose.Types.ObjectId());
      const clausesFor = (sortDir) =>
        applyCursorCondition(
          {},
          { sortField: SORT_FIELD, sortDir, cursor: { v: null, id }, valueType: 'date' }
        ).$and[1].$or;
      const asc = clausesFor(1);
      const desc = clausesFor(-1);
      // 平局子句：两条都以"空值等值 + _id 同向"收口，op 与方向配对
      expect(asc[0]).toEqual({ [SORT_FIELD]: null, _id: { $gt: new mongoose.Types.ObjectId(id) } });
      expect(desc[0]).toEqual({
        [SORT_FIELD]: null,
        _id: { $lt: new mongoose.Types.ObjectId(id) },
      });
      // 升序：空值块在头部，块之后还有全部有值文档 ⇒ 必须并一条 $ne:null 接住它们
      expect(asc).toContainEqual({ [SORT_FIELD]: { $ne: null } });
      // 倒序：块在尾部，回头去捞有值文档会把已经翻过的那一整段**再发一遍**
      expect(desc).not.toContainEqual({ [SORT_FIELD]: { $ne: null } });
    });

    test('未识别的 valueType 在两条路径上都是 400（空值分支不得绕过收口）', () => {
      const id = String(new mongoose.Types.ObjectId());
      for (const v of ['2026-09-01T00:00:00.000Z', null]) {
        expect(() =>
          applyCursorCondition(
            {},
            { sortField: SORT_FIELD, sortDir: -1, cursor: { v, id }, valueType: 'data' }
          )
        ).toThrow('分页游标无效，请从第一页重新查询');
      }
    });
  });

  describe('真库层：混合列表的整条翻页链', () => {
    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
      await Inspection.deleteMany({ title: new RegExp(`^${TAG}`) });
      await Inspection.create([
        dated(`${TAG} A`, 3),
        dated(`${TAG} B`, 2),
        dated(`${TAG} C`, 1),
        { title: `${TAG} D`, inspectionType: 'daily' }, // 不传 ⇒ 文档里没有这个键
        { title: `${TAG} E`, planStartTime: null, inspectionType: 'daily' }, // 显式 null
      ]);
    });

    afterAll(async () => {
      await Inspection.deleteMany({ title: new RegExp(`^${TAG}`) });
    });

    const listPage = (args) =>
      InspectionService.getInspections({
        limit: 1,
        search: TAG,
        dataScope: { type: 'all' },
        ...args,
      });

    test('前提自证：夹具形态与倒序位置（否则后面的判据是空的）', async () => {
      const rawD = await Inspection.find({ title: `${TAG} D` }).lean();
      expect(rawD).toHaveLength(1);
      expect('planStartTime' in rawD[0]).toBe(false);
      const rawE = await Inspection.find({ title: `${TAG} E` }).lean();
      expect(rawE[0].planStartTime).toBeNull();
      // 三条有日期的必须各不相同：T2 用它们当"确定能数对"的锚
      expect(await Inspection.countDocuments({ title: new RegExp(`^${TAG}`) })).toBe(5);
      const first = await listPage({ page: 1 });
      expect(first.inspections[0].title).toBe(`${TAG} A`);
    });

    test('逐页走完：不下 400、不漏有值记录，并且真的能触及空值块', async () => {
      const seen = [];
      let cursor = null;
      let steps = 0;
      for (; steps < 10; steps += 1) {
        const page = await listPage(cursor ? { cursor } : { page: 1 });
        const items = page.inspections || [];
        // 收尾口径：游标模式下"还有下一页"与"带游标"必须同真同假。
        // 首页走的是 offset 模式，它的响应体里根本没有 hasMore 这一项（只有 count），
        // 所以那条不变式只对游标模式的页施加——这一处形状不对称已登记为待决。
        if (page.hasMore !== undefined) {
          expect(Boolean(page.nextCursor)).toBe(page.hasMore === true);
        }
        for (const doc of items) {
          seen.push(doc.title);
          if (page.nextCursor) expect(() => decodeCursor(page.nextCursor)).not.toThrow();
        }
        if (page.hasMore === false || items.length === 0) break;
        if (!page.nextCursor) break;
        cursor = page.nextCursor;
      }
      expect(steps).toBeLessThan(9); // 链必须收敛，不能靠循环上限兜住
      // 三条有日期的记录各出现一次（键值互异 ⇒ 顺序与条数都可依赖）
      for (const t of [`${TAG} A`, `${TAG} B`, `${TAG} C`]) {
        expect(seen.filter((x) => x === t)).toHaveLength(1);
      }
      // 判据核心：空值块（缺键或显式 null）**两条都要到齐，且各只出现一次**。
      // 修复前这里恒为 0 条——范围比较跨不到 null，列表在 C 之后就 hasMore:false。
      // 早先只断"至少被触及一次"，是因为调用点 `.sort()` 还没带 `_id` 次级键、
      // 块内会漂移吞一条；现在排序是全序 ⇒ 弱断言换成精确断言。
      const blockSeen = seen.filter((t) => t === `${TAG} D` || t === `${TAG} E`);
      expect(blockSeen.sort()).toEqual([`${TAG} D`, `${TAG} E`]);
      expect(seen.sort()).toEqual(
        [`${TAG} A`, `${TAG} B`, `${TAG} C`, `${TAG} D`, `${TAG} E`].sort()
      );
    });

    test('升序翻页（服务当前没走的方向）：空值页之后必须还能接住全部有值记录', async () => {
      // 为什么单独钉这条：倒序时空值块在**尾部**，接错方向只是"少尾巴"；
      // 升序时空值块在**头部**，一旦空值页的条件只写 `{f:null,_id:$gt}` 而丢掉
      // `{f:$ne:null}` 尾巴，翻页会在块尾**提前收尾**，用户看到"就这些了"
      // 而实际后面还有整块有日期记录。
      // 这里直接驱动工具层（服务只有倒序调用点），但条件与查询都走真库，
      // 不吃任何读代码得出的假设。
      const walk = async () => {
        const seen = [];
        let cursor = null;
        for (let step = 0; step < 8; step += 1) {
          const base = { title: new RegExp(`^${TAG}`) };
          const query = cursor
            ? applyCursorCondition(base, {
                sortField: SORT_FIELD,
                sortDir: 1,
                cursor,
                valueType: 'date',
              })
            : base;
          const docs = await Inspection.find(query)
            // 升序的次级键方向与子句 `{f:v,_id:{$gt:id}}` 一致（生产调用点都是倒序，
            // 这条用例是给"将来有人加升序调用点"留的可依赖模板）
            .sort({ [SORT_FIELD]: 1, _id: 1 })
            .limit(2)
            .lean();
          const page = docs.slice(0, 1);
          if (page.length === 0) break;
          seen.push(...page.map((d) => d.title));
          if (docs.length < 2) break; // 没有第 limit+1 条 ⇒ 真的到底
          const last = page[0];
          const v = last[SORT_FIELD] === undefined ? null : last[SORT_FIELD];
          cursor = decodeCursor(encodeCursor({ v, id: String(last._id) }));
        }
        return seen;
      };

      const seen = await walk();
      const valued = [`${TAG} A`, `${TAG} B`, `${TAG} C`];
      const block = [`${TAG} D`, `${TAG} E`];
      // 不重复：升序的空值页与有值页条件互斥（$ne:null vs 范围），不该吐出两条同 _id
      expect(new Set(seen).size).toBe(seen.length);
      // 判据核心（M3 的杀伤点）：空值页之后**必须**还能接住全部有值记录。
      // 丢掉 `{f:{$ne:null}}` 尾巴 ⇒ 翻页走到空值块尾就再也接不住任何有值文档（本用例判红）。
      expect(seen.filter((t) => valued.includes(t))).toEqual([`${TAG} C`, `${TAG} B`, `${TAG} A`]);
      // 升序把空值块排在**头部**（与倒序相反），所以第一条必是空值文档
      expect(block).toContain(seen[0]);
      // 5 条全到：排序带上 `_id` 后块内是全序，升序方向也不该再少给空值文档
      expect(seen).toHaveLength(5);
    });
  });

  describe('真库层：全是空值排序键的列表', () => {
    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
      await Inspection.deleteMany({ title: new RegExp(`^${TAG2}`) });
      // 两条都**不带**该键（不放显式 null）：这样"第一页末尾是缺键文档"是必然事件，
      // 缺陷 ① 的复现就不依赖块内顺序。
      await Inspection.create([
        { title: `${TAG2} D`, inspectionType: 'daily' },
        { title: `${TAG2} E`, inspectionType: 'daily' },
      ]);
    });

    afterAll(async () => {
      await Inspection.deleteMany({ title: new RegExp(`^${TAG2}`) });
      // 本文件是这段链路里唯一连库的，收尾不关就会留下活跃句柄（jest 报 worker 无法退出）
      if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
    });

    const listPage = (args) =>
      InspectionService.getInspections({
        limit: 1,
        search: TAG2,
        dataScope: { type: 'all' },
        ...args,
      });

    test('第一页末尾就是缺键文档：它下发的游标必须能被服务自己吃回去', async () => {
      // 首页只能走 offset 模式（没有游标可传），而它的响应体里没有 hasMore，
      // 只有 count 与 nextCursor —— 所以这里钉 nextCursor 本身。
      const p1 = await listPage({ page: 1 });
      expect(p1.count).toBe(2);
      expect(p1.nextCursor).toBeTruthy();
      const raw = await Inspection.findById(p1.inspections[0]._id).lean();
      expect('planStartTime' in raw).toBe(false);
      expect(() => decodeCursor(p1.nextCursor)).not.toThrow();
      // 修前：这里抛 400「请从第一页重新查询」，而回到第一页又会拿到同一个游标
      const p2 = await listPage({ cursor: p1.nextCursor });
      expect(Array.isArray(p2.inspections)).toBe(true);
    });

    test('空值块内的续翻是集合语义：按 _id 比较，恰好拿到块内其余那一条', async () => {
      const block = await Inspection.find({ title: new RegExp(`^${TAG2}`) })
        .sort({ _id: 1 })
        .lean();
      expect(block).toHaveLength(2);
      const [older, newer] = block;
      const res = await listPage({ cursor: encodeCursor({ v: null, id: String(newer._id) }) });
      // 修前：v=null 被 new Date(null) 压成 1970 ⇒ 这里恒空，用户看到"到底了"
      expect(res.inspections.map((d) => String(d._id))).toEqual([String(older._id)]);
    });
  });
});
