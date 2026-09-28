'use strict';

/**
 * 审计日志"按 IP 查"必须覆盖同一地址的全部等价文本形态
 *
 * 盘点实测（2026-09-19，本地 dev 库 6846 条 auditlogs，只读）：
 *   存储文本 ::ffff:127.0.0.1 = 3553 条；127.0.0.1 = 2089 条（同一地址）
 *   管理员搜 "127.0.0.1" → 命中 2089 条 ⇒ **静默漏掉 3553 条（该地址的 63%）**，HTTP 200 无提示。
 *
 * 成因：查询侧与导出侧各写一份
 *   `const ipVariants = [...new Set([normalizeIP(ip), String(ip).trim()])]`
 * ——变体是从**输入字符串**推导的。两个方向只覆盖了一半：
 *   输入 `::ffff:1.2.3.4` ⇒ 变体 [规范, 原始] 都有 ⇒ 能命中混合存储（这半边有注释，是刻意做的）
 *   输入 `1.2.3.4`       ⇒ normalizeIP 与原始值**相同** ⇒ 变体只有一个 ⇒ 映射形态入库的行进不来
 * 即写这条逻辑的人想到"用户可能贴 ::ffff: 来查"，没想到"库里存的可能就是 ::ffff:"。
 * Node 在 IPv6 栈下 `req.ip` 恒为 `::ffff:a.b.c.d` ⇒ 入库侧那个形态是**默认形态**。
 *
 * 为什么按缺陷报而不是"数据脏"：这是审计系统，检索结果不完整比报错危险——
 * 与 （success 静默折成 false 导致"以为筛过、实际看到另一个集合"）同一条判据。
 *
 * 已落地修法：变体从**地址**推导，收进 `ipUtils.ipQueryVariants/ipQueryCondition`
 * （唯一事实来源，两侧共用），IPv4 规范形态额外并入 `::ffff:X`。
 * 本文件因此从"缺陷登记"转为**回归锁**，并额外钉两条防再漂移：
 *  1) 全仓不得再出现内联的 `[...new Set([normalize...` 变体推导（防第三处另写一份）；
 *  2) 每个变体归一化后仍等于目标地址（防"为凑命中而放宽"把修复退化成过宽匹配）。
 */

const fs = require('fs');
const path = require('path');
const { buildAuditQuery } = require('../../utils/auditQuery');
const { buildExportQuery } = require('../../services/reportExportService');
const { ipQueryVariants, ipQueryCondition, normalizeIP } = require('../../utils/ipUtils');

// 查询侧对"单值"与"多值"用了两种形状（ variants.length > 1 ? {$in} : 裸字符串 ），
// 断言前统一成数组，避免把形状差异误判成命中差异
const ipFilterValues = (query) => {
  if (typeof query.ip === 'string') return [query.ip];
  if (query.ip && Array.isArray(query.ip.$in)) return query.ip.$in;
  return [];
};

const queryVariants = (ip) => ipFilterValues(buildAuditQuery({ query: { ip } }).query);
const exportVariants = (ip) => ipFilterValues(buildExportQuery('audit', { ip, dateFilter: {} }));

describe('zzqA 审计 IP 检索的等价文本形态', () => {
  describe('夹具自证（必须是普通断言）', () => {
    test('输入映射写法时两侧都已给出双变体（原有正确的一半，修法不许退回去）', () => {
      for (const variants of [queryVariants, exportVariants]) {
        const v = variants('::ffff:127.0.0.1');
        expect(v).toContain('127.0.0.1');
        expect(v).toContain('::ffff:127.0.0.1');
      }
    });

    test('两个构建器都真的产出了 ip 条件（没接错函数、没被前面的分支吃掉）', () => {
      expect(queryVariants('127.0.0.1').length).toBeGreaterThan(0);
      expect(exportVariants('127.0.0.1').length).toBeGreaterThan(0);
    });

    test('变体里每个值归一化后都必须仍等于目标地址（禁止为凑命中而放宽）', () => {
      for (const target of ['127.0.0.1', '10.20.30.40']) {
        for (const variants of [queryVariants, exportVariants]) {
          for (const v of variants(target)) {
            expect(normalizeIP(v)).toBe(target);
          }
        }
      }
    });
  });

  describe('修复后的语义（曾以 test.failing 记账，2026-09-20 落地）', () => {
    test('查询侧：输入 127.0.0.1 时变体必须同时含 ::ffff:127.0.0.1', () => {
      expect(queryVariants('127.0.0.1')).toContain('::ffff:127.0.0.1');
    });

    test('导出侧：与查询侧同口径（导出即所见，两侧不许一边修好一边漏）', () => {
      expect(exportVariants('127.0.0.1')).toContain('::ffff:127.0.0.1');
    });

    test('两侧变体集合逐项相等（这才叫"导出即所见"）', () => {
      for (const ip of ['127.0.0.1', '::ffff:127.0.0.1', '2001:db8::1']) {
        expect([...queryVariants(ip)].sort()).toEqual([...exportVariants(ip)].sort());
      }
    });
  });

  describe('判据本身：IPv6 不许被造出非法变体，非 IP 输入不许变成"匹配一切"', () => {
    test('纯 IPv6 地址不会补出 ::ffff: 形态（那是非法文本，只会引入噪声条件）', () => {
      expect(ipQueryVariants('2001:db8::1')).toEqual(['2001:db8::1']);
      expect(ipQueryCondition('2001:db8::1')).toBe('2001:db8::1');
    });

    test('带原始写法差异时三个形态并存，且去重', () => {
      expect(ipQueryVariants(' 10.0.0.7 ')).toEqual(['10.0.0.7', '::ffff:10.0.0.7']);
      expect(ipQueryVariants('::ffff:10.0.0.7')).toEqual(['10.0.0.7', '::ffff:10.0.0.7']);
      expect(ipQueryVariants('010.0.0.7')).toEqual(['010.0.0.7']); // 歧义形态：此后归一化为 null
    });

    test('空/非字符串输入返回空数组 ⇒ 条件不落库而不是匹配一切', () => {
      expect(ipQueryVariants('')).toEqual([]);
      expect(ipQueryVariants(undefined)).toEqual([]);
      expect(ipQueryCondition(null)).toBeNull();
    });

    test('单值退化为等值、多值用 $in（索引形状与修复前一致）', () => {
      expect(ipQueryCondition('2001:db8::1')).toBe('2001:db8::1');
      expect(ipQueryCondition('10.0.0.7')).toEqual({ $in: ['10.0.0.7', '::ffff:10.0.0.7'] });
    });
  });

  describe('防再漂移：变体推导只能有一份实现', () => {
    test('src 下不再出现内联的 [归一化值, 原始值] 变体推导', () => {
      const root = path.join(__dirname, '..', '..');
      const offenders = [];
      const walk = (dir) => {
        for (const name of fs.readdirSync(dir)) {
          const full = path.join(dir, name);
          const stat = fs.statSync(full);
          if (stat.isDirectory()) {
            if (name === 'tests' || name === 'node_modules') continue;
            walk(full);
          } else if (
            name.endsWith('.js') &&
            /new Set\(\[\s*normalized|new Set\(\[\s*\w*[nN]ormaliz/.test(
              fs.readFileSync(full, 'utf8')
            )
          ) {
            offenders.push(path.relative(root, full));
          }
        }
      };
      walk(root);
      expect(offenders).toEqual([]);
    });

    test('查询侧与导出侧都走 ipUtils 的同一把尺子', () => {
      const read = (p) => fs.readFileSync(path.join(__dirname, '..', '..', p), 'utf8');
      expect(read('utils/auditQuery.js')).toMatch(/ipQueryCondition/);
      expect(read('services/reportExportService.js')).toMatch(/ipQueryCondition/);
    });
  });
});
