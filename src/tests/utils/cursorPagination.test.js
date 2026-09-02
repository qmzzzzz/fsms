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
      expect(q.$and[1].$or).toHaveLength(2);
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
});
