/**
 * 游标分页工具单测（E-2）
 * 覆盖：编解码往返、非法游标拒绝、游标条件构造（升/降序、$and 包裹、
 * 与既有 $or 共存）、limit+1 结果裁剪与 nextCursor 语义
 */

const mongoose = require('mongoose');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
  MAX_CURSOR_VALUE_LENGTH,
} = require('../../utils/cursorPagination');
const ApiError = require('../../utils/ApiError');

const validId = () => String(new mongoose.Types.ObjectId());

describe('utils/cursorPagination', () => {
  describe('encode/decode 往返', () => {
    test('日期排序键 + ObjectId 往返一致', () => {
      const id = validId();
      const now = new Date('2026-08-30T12:34:56.789Z');
      const decoded = decodeCursor(encodeCursor({ v: now, id }));
      expect(new Date(decoded.v).getTime()).toBe(now.getTime());
      expect(decoded.id).toBe(id);
    });

    test('字符串排序键往返一致', () => {
      const id = validId();
      const decoded = decodeCursor(encodeCursor({ v: 'DEV-0007', id }));
      expect(decoded.v).toBe('DEV-0007');
      expect(decoded.id).toBe(id);
    });

    test('排序键为 null 也可往返（边界值不崩溃）', () => {
      const decoded = decodeCursor(encodeCursor({ v: null, id: validId() }));
      expect(decoded.v).toBeNull();
    });
  });

  // L-14：decodeCursor 此前只校验「v 键存在」，对象/数组形态直接放行，
  // 而 string 分支会把它们原样透传进查询条件 → 静默错页而非报错。
  // 以下用例锁定「非标量一律拒绝」，防回归。
  describe('decodeCursor：v 必须为标量（L-14）', () => {
    const encode = (v) =>
      Buffer.from(JSON.stringify({ v, id: validId() }), 'utf8').toString('base64url');

    test.each([
      ['对象', { $gt: '' }],
      ['数组', ['a', 'b']],
      ['嵌套对象', { a: { b: 1 } }],
      ['布尔', true],
    ])('v 为%s → 400（拒绝查询注入面）', (_name, v) => {
      expect(() => decodeCursor(encode(v))).toThrow(ApiError);
    });

    test('v 为超长字符串 → 400（封住超长入参）', () => {
      expect(() => decodeCursor(encode('x'.repeat(MAX_CURSOR_VALUE_LENGTH + 1)))).toThrow(ApiError);
    });

    test('v 为合法长度的字符串/数字仍放行', () => {
      expect(decodeCursor(encode('DEV-0007')).v).toBe('DEV-0007');
      expect(decodeCursor(encode(42)).v).toBe(42);
    });
  });

  describe('decodeCursor 非法输入一律 400', () => {
    const badInputs = [
      ['非字符串', 12345],
      ['空串', ''],
      ['超长字符串', 'a'.repeat(600)],
      ['非 base64url JSON', '!!!not-base64!!!'],
      ['合法 JSON 但非对象', Buffer.from('"str"', 'utf8').toString('base64url')],
      ['数组', Buffer.from('[]', 'utf8').toString('base64url')],
      ['缺少 v 字段', Buffer.from(JSON.stringify({ id: validId() }), 'utf8').toString('base64url')],
      ['id 非字符串', Buffer.from(JSON.stringify({ v: 1, id: 2 }), 'utf8').toString('base64url')],
      [
        'id 非 ObjectId 格式',
        Buffer.from(JSON.stringify({ v: 1, id: 'xyz' }), 'utf8').toString('base64url'),
      ],
    ];

    test.each(badInputs)('%s → ApiError 400', (_name, input) => {
      expect(() => decodeCursor(input)).toThrow(ApiError);
      try {
        decodeCursor(input);
      } catch (err) {
        expect(err.statusCode).toBe(400);
      }
    });
  });

  describe('applyCursorCondition', () => {
    test('无游标时原样返回基础查询', () => {
      const base = { status: 'pending' };
      expect(
        applyCursorCondition(base, { sortField: 'occurredAt', sortDir: -1, cursor: null })
      ).toBe(base);
    });

    test('降序游标生成 (field < v) OR (field == v AND _id < id) 并以 $and 包裹', () => {
      const id = validId();
      const v = new Date('2026-08-30T00:00:00Z');
      const q = applyCursorCondition(
        { status: 'pending' },
        {
          sortField: 'occurredAt',
          sortDir: -1,
          cursor: { v: v.toISOString(), id },
          valueType: 'date',
        }
      );
      expect(q.$and).toHaveLength(2);
      expect(q.$and[0]).toEqual({ status: 'pending' });
      const [ltBranch, tieBranch] = q.$and[1].$or;
      expect(ltBranch.occurredAt.$lt.getTime()).toBe(v.getTime());
      expect(tieBranch.occurredAt.getTime()).toBe(v.getTime());
      expect(String(tieBranch._id.$lt)).toBe(id);
    });

    test('升序游标使用 $gt', () => {
      const q = applyCursorCondition(
        {},
        {
          sortField: 'deviceCode',
          sortDir: 1,
          cursor: { v: 'DEV-3', id: validId() },
          valueType: 'string',
        }
      );
      const [gtBranch] = q.$and[1].$or;
      expect(gtBranch.deviceCode.$gt).toBe('DEV-3');
    });

    test('基础查询自带 $or（搜索）时不被覆盖', () => {
      const base = { $or: [{ a: 1 }, { b: 2 }] };
      const q = applyCursorCondition(base, {
        sortField: 'occurredAt',
        sortDir: -1,
        cursor: { v: new Date().toISOString(), id: validId() },
      });
      expect(q.$and[0].$or).toEqual([{ a: 1 }, { b: 2 }]);
      // 钉的是"游标条件与 baseQuery 的 $or 各占一个 $and 成员、没有互相覆盖"这件事本身。
      // 原来这里写 `toHaveLength(2)`：条数不是判据（倒序还带着空值块子句，条数会随语义
      // 演进变化），拿它当判据既挡不住"子句被换成别的"，又会在无关改动上假红。
      const clauses = q.$and[1].$or;
      expect(clauses.some((c) => c.occurredAt && c.occurredAt.$lt instanceof Date)).toBe(true);
      expect(clauses.some((c) => c._id && c._id.$lt instanceof mongoose.Types.ObjectId)).toBe(true);
      expect(clauses.every((c) => 'occurredAt' in c || '_id' in c)).toBe(true);
    });

    test('date 类型游标值非法时抛 400', () => {
      expect(() =>
        applyCursorCondition(
          {},
          {
            sortField: 'occurredAt',
            sortDir: -1,
            cursor: { v: 'not-a-date', id: validId() },
            valueType: 'date',
          }
        )
      ).toThrow(ApiError);
    });

    test('number 类型游标值非法时抛 400', () => {
      expect(() =>
        applyCursorCondition(
          {},
          {
            sortField: 'seq',
            sortDir: -1,
            cursor: { v: 'NaN种子', id: validId() },
            valueType: 'number',
          }
        )
      ).toThrow(ApiError);
    });

    test('number 类型游标值被转换为数值', () => {
      const q = applyCursorCondition(
        {},
        {
          sortField: 'seq',
          sortDir: -1,
          cursor: { v: '42', id: validId() },
          valueType: 'number',
        }
      );
      expect(q.$and[1].$or[0].seq.$lt).toBe(42);
    });
  });

  describe('buildCursorResult', () => {
    const doc = (code) => ({ _id: new mongoose.Types.ObjectId(), deviceCode: code });

    test('docs 超过 limit：截断 + hasMore + nextCursor 指向最后一条', () => {
      const docs = [doc('A'), doc('B'), doc('C')];
      const { items, hasMore, nextCursor } = buildCursorResult(docs, 2, 'deviceCode');
      expect(items.map((d) => d.deviceCode)).toEqual(['A', 'B']);
      expect(hasMore).toBe(true);
      const decoded = decodeCursor(nextCursor);
      expect(decoded.v).toBe('B');
      expect(decoded.id).toBe(String(docs[1]._id));
    });

    test('docs 不超过 limit：hasMore=false 且无游标', () => {
      const docs = [doc('A'), doc('B')];
      const { items, hasMore, nextCursor } = buildCursorResult(docs, 2, 'deviceCode');
      expect(items).toHaveLength(2);
      expect(hasMore).toBe(false);
      expect(nextCursor).toBeNull();
    });

    test('空结果安全返回', () => {
      const { items, hasMore, nextCursor } = buildCursorResult([], 10, 'deviceCode');
      expect(items).toEqual([]);
      expect(hasMore).toBe(false);
      expect(nextCursor).toBeNull();
    });
  });

  /**
   * F-169：游标值上限 ⇄ 服务真正下发的排序键宽度（跨文件不变式）
   *
   * 修前的事实：`MAX_CURSOR_VALUE_LENGTH` 为 32，而设备列表用 `deviceCode` 作排序键
   * （`DeviceService.getDevices` 是全仓唯一的 `valueType:'string'` 调用点），其合法宽度
   * 上限由 `models/FireDevice` 的 `maxlength:50` 决定（`deviceRoutes.js` 的
   * `isLength({max:50})` 与它对齐，50 字符可入库由 zzqoder_deviceCodeCap.test.js 钉着）。
   * ⇒ 某页最后一条的编码落在 33–50 时，服务照样下发 nextCursor，客户端原样回传却被
   * `decodeCursor` 拒成 400——**翻页从这一页起死掉，且服务端一条日志都没有**。
   *
   * 为什么旧用例抓不到：上面「v 为超长字符串 → 400」那条把期望长度**算自同一个常量**
   * （`MAX_CURSOR_VALUE_LENGTH + 1`），上限从 32 改成任何值它都跟着变绿。
   * 所以下面两条的期望值一律取自**模型 schema**（与被检对象不同一侧），不抄数字。
   */
  describe('游标值上限必须覆盖服务下发的排序键宽度（F-169）', () => {
    const FireDevice = require('../../models/FireDevice');

    /** deviceCode 的合法最大长度：事实来源是模型，不是测试里抄的一个数 */
    const widestLegalCode = () => {
      const declared = FireDevice.schema.path('deviceCode').options.maxlength;
      const n = Array.isArray(declared) ? declared[0] : declared;
      // 前提自证：声明形态变了（改成标量、或被删）就先红在这里，而不是让下面几条静默空跑
      expect(Number.isInteger(n)).toBe(true);
      return n;
    };

    test('上限 ≥ 最宽合法排序键，同时仍是远小于整条游标的窄闸', () => {
      expect(MAX_CURSOR_VALUE_LENGTH).toBeGreaterThanOrEqual(widestLegalCode());
      expect(MAX_CURSOR_VALUE_LENGTH).toBeLessThan(512);
    });

    test('端到端：最宽合法编码所在页下发的游标能被自己的解码链吃回去', () => {
      const code = 'Z'.repeat(widestLegalCode());
      const docs = [
        { _id: new mongoose.Types.ObjectId(), deviceCode: 'ZZ-EDGE-A' },
        { _id: new mongoose.Types.ObjectId(), deviceCode: code },
        { _id: new mongoose.Types.ObjectId(), deviceCode: 'ZZ-EDGE-C' },
      ];
      // 两条前提自证：本页最后一条确实是那条超长编码，且服务确实会下发游标
      // （否则 decodeCursor 收到 null、后面全部空跑）
      const page1 = buildCursorResult(docs, 2, 'deviceCode');
      expect(page1.hasMore).toBe(true);
      expect(page1.items[1].deviceCode).toBe(code);
      expect(page1.nextCursor).not.toBeNull();

      const decoded = decodeCursor(page1.nextCursor); // 修前：33–50 长度的编码在这一步抛 400
      expect(decoded.v).toBe(code);
      const q = applyCursorCondition(
        {},
        { sortField: 'deviceCode', sortDir: 1, cursor: decoded, valueType: 'string' }
      );
      expect(q.$and[1].$or[0].deviceCode.$gt).toBe(code);
    });
  });
});
