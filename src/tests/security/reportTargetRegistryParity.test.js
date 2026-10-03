/**
 * POST /api/security/report：路由的类型清单与控制器的核验登记表必须同一张表
 * （2026-10-03 审计线，针对并行 Agent 的 `27f4243`）
 *
 * 缺陷形状是**清单漂移**，不是当前行为错误：
 *   · 路由 `src/routes/securityRoutes.js:94` 自己写了一份
 *     `REPORT_TARGET_TYPES = ['user','device','alarm','system']`；
 *   · 控制器 `src/controllers/securityController.js` 另写了一份
 *     `REPORT_TARGET_KINDS = { user, device, alarm }`（system 刻意缺席）；
 *   · 核验入口是 `const kind = REPORT_TARGET_KINDS[targetType]; if (!kind) return null;`
 *     ——这句只在"路由枚举里除 system 之外再没有别的值"时才是安全的。
 * 于是给路由枚举加第五个值（`inspection`、`visitor`……）的这次改动，
 * 会让 `isReportRecordType`（由 `REPORT_TARGET_TYPES.filter(t => t !== 'system')` 派生）
 * **要求**一个 ObjectId 形态的 targetId，而控制器把该类型当成 system 一样**免检放行**：
 * 一条未核验、未存在、越权的 `riskLevel:'high'` 审计行照样落库——
 * 正是 `27f4243` 想收口的那个投毒面，从一个新增枚举值上原地复活。
 * 今天这条路径不可达（枚举只有 4 个值、4 个都有对应臂），所以本文件用的是
 * 源码闸而非 HTTP 真跑：**要防的正是"下一次改动"**，那是一行加在枚举里的普通改动，
 * 不会有人想到要去动控制器。（同一形状的先例：第 11 轮"user:lock 控制器要、路由闸不要"。）
 *
 * 与仓内既有做法一致的两点：
 *  1) 派生而非抄第二份清单——`RESPONSE_EXCLUDE_PHONE_VISIBLE` 那条用例钉的就是
 *     "变体必须由同一张字段表派生"，这里钉 `REPORT_RECORD_TYPES` 必须由
 *     `REPORT_TARGET_TYPES.filter(...)` 派生；
 *  2) 文本闸自带反向自证（合成样本）：判据本身可能是恒真的（路径写错、锚点没命中、
 *     正则读进注释），所以除了跑真实文件，还要把同一对抽取函数喂给
 *     "加了第五个类型"和"登记表多一个孤儿键"两份合成源码，它们**必须**被判为不一致。
 *
 * 修法建议（写给该 lane 的作者，不是本文件的内容）：
 *  把类型清单挪进 `src/constants/`（route 与 controller 共用），
 *  或让 `!kind` 分支 fail-closed（未知类型 ⇒ 400），二者任取其一即可让本闸变成保险。
 */

const fs = require('fs');
const path = require('path');

const ROUTE_FILE = path.join(__dirname, '..', '..', 'routes', 'securityRoutes.js');
const CONTROLLER_FILE = path.join(__dirname, '..', '..', 'controllers', 'securityController.js');

/** 从路由源码里取 `const REPORT_TARGET_TYPES = [...]` 的字面量成员 */
const extractRouteTypes = (src) => {
  const m = src.match(/const REPORT_TARGET_TYPES\s*=\s*\[([^\]]*)\]/);
  if (!m) throw new Error('路由里的 REPORT_TARGET_TYPES 锚点未命中（改名或换写法，请同步本闸）');
  return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
};

/** 从控制器源码里取 `const REPORT_TARGET_KINDS = { ... }` 的顶层键（两空格缩进的 `k: {`） */
const extractRegistryKeys = (src) => {
  const start = src.indexOf('const REPORT_TARGET_KINDS');
  if (start === -1) throw new Error('控制器里的 REPORT_TARGET_KINDS 锚点未命中（改名请同步本闸）');
  const end = src.indexOf('\n};', start);
  if (end === -1) throw new Error('REPORT_TARGET_KINDS 的收尾未命中');
  const block = src.slice(start, end);
  return [...block.matchAll(/^ {2}([A-Za-z_]\w*):\s*\{/gm)].map((x) => x[1]);
};

/** 两侧差集：recordTypes = 枚举去掉 system */
const diff = (enumRecordKeys, registryKeys) => ({
  onlyInRoute: enumRecordKeys.filter((k) => !registryKeys.includes(k)).sort(),
  onlyInRegistry: registryKeys.filter((k) => !enumRecordKeys.includes(k)).sort(),
});

describe('安全举报的目标类型清单与核验登记表同源', () => {
  const routeSrc = fs.readFileSync(ROUTE_FILE, 'utf8');
  const controllerSrc = fs.readFileSync(CONTROLLER_FILE, 'utf8');
  const routeTypes = extractRouteTypes(routeSrc);
  const registryKeys = extractRegistryKeys(controllerSrc);
  const recordTypes = routeTypes.filter((t) => t !== 'system');

  // 抽取器不能返回空集：路径写错、锚点没命中、正则读进注释，都会让下面的
  // toEqual([]) 变成"恒真空通过"。先钉总体形态。
  test('抽取自证：两份清单都真的被读到（否则本闸恒真）', () => {
    expect(routeTypes).toEqual(['user', 'device', 'alarm', 'system']);
    expect(registryKeys).toEqual(['user', 'device', 'alarm']);
  });

  test('一致性：枚举的每一个记录型都有核验臂，登记表没有孤儿键', () => {
    expect(diff(recordTypes, registryKeys)).toEqual({ onlyInRoute: [], onlyInRegistry: [] });
  });

  test('system 是唯一免检类型，且它不在登记表里（免检必须是刻意的、可枚举的）', () => {
    expect(routeTypes).toContain('system');
    expect(registryKeys).not.toContain('system');
    // 路由同时禁止 system 携带 targetId——免检臂只有在"带不上 ID"时才成立
    expect(routeSrc).toMatch(/body\('targetId'\)[\s\S]{0,120}isReportSystemType/);
  });

  test('记录型清单必须由枚举派生，而不是第二份手写清单', () => {
    // 手写第二份 ⇒ 加类型时静默漏一处，与本次缺陷同形
    expect(routeSrc).toMatch(
      /const REPORT_RECORD_TYPES\s*=\s*REPORT_TARGET_TYPES\.filter\(\s*\(?t\)?\s*=>\s*t !== 'system'\s*\)/
    );
  });

  test('反向自证：合成样本必须被判为不一致（否则本闸是空的）', () => {
    // ① 给枚举加第五个类型、登记表不动 ⇒ 该类型免检（就是本文件头描述的那次改动）
    const driftedRoute = routeSrc.replace(
      /const REPORT_TARGET_TYPES\s*=\s*\[[^\]]*\]/,
      "const REPORT_TARGET_TYPES = ['user', 'device', 'alarm', 'system', 'inspection'];"
    );
    const driftedTypes = extractRouteTypes(driftedRoute).filter((t) => t !== 'system');
    expect(diff(driftedTypes, registryKeys)).toEqual({
      onlyInRoute: ['inspection'],
      onlyInRegistry: [],
    });
    // 而且漂移后的样本仍能证明"免检臂会被要求填 ID"——即缺陷确实成立，不是修辞
    expect(driftedRoute).toContain('isReportRecordType');
    expect(driftedTypes).toContain('inspection');

    // ② 登记表多一个枚举里没有的键 ⇒ 永远不会被路由放行（死臂）
    expect(diff(recordTypes, [...registryKeys, 'inspection'])).toEqual({
      onlyInRoute: [],
      onlyInRegistry: ['inspection'],
    });

    // ③ 未漂移的对照组：真实两份清单必须判为一致（①② 的反面，缺它则两条差集断言无意义）
    expect(diff(recordTypes, registryKeys)).toEqual({ onlyInRoute: [], onlyInRegistry: [] });
  });
});
