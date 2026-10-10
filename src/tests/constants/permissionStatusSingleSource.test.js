/**
 * 取值清单的单一来源对账（F-137 权限三组 + F-138 账户状态 + F-141 IP 名单类型）
 *
 * 为什么需要：`PERMISSION_TYPES` / `PERMISSION_METHODS` / `RESOURCE_STATUSES` /
 * `USER_STATUS` 这四组值此前各有 4~6 处**字面量副本**，分布在 Mongoose `enum`、
 * express-validator 的 `isIn(...)`、服务层的过滤白名单、以及 OpenAPI 生成器。
 * 副本的失效方式不是"今天错了"（今天四处内容完全相同，所有测试全绿），
 * 而是"加一档的那一天错"，且三种分叉各有不同症状：
 *   - 只改 constants ⇒ 路由 400 掉新值，schema 永远收不到，新档实际不可用；
 *   - 只改 schema ⇒ 校验放行、`save()` 抛 ValidationError；
 *   - User 那一组还有第三种更坏的：`userService.buildListQuery` 对**不认识的状态值
 *     静默丢掉整个过滤条件**（返回全量用户而不是 400）——见最后一组用例。
 *
 * 口径照搬 constants/audit.js 已经建立的家族规范：值只有一份，其余位置一律引用。
 * 因此本文件既有"运行时内容对账"，也有"引用点数量对账"——后者专门用来抓
 * "只改了一处、其余副本还留着字面量"的半拉子重接线：数量掉 1 就红。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

/**
 * 代码视图：去掉**整行注释**（`// ...`、`* ...`、`/* ... *\/` 的续行）。
 * 对账"某段源码里不该再出现某个写法"时必须先过这一层，否则头注释里对旧写法的
 * 引用会让用例红——而那种红没有意义，改注释措辞就能消掉，等于把用例绑在文案上。
 * 行尾的跟随注释**保留**在视图里（`code; // ['a','b']` 这种仍然会被抓到），
 * 因为真正的副本只会出现在代码位置。口径同 F-128（合规门禁跑在代码视图上）。
 */
const codeOnly = (src) =>
  src
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join('\n');

const {
  PERMISSION_TYPES,
  PERMISSION_METHODS,
  RESOURCE_STATUSES,
} = require('../../constants/permission');
const { USER_STATUS } = require('../../utils/constants');

const User = require('../../models/User');
const Permission = require('../../models/Permission');
const Role = require('../../models/Role');

const isInCount = (src, name) =>
  (codeOnly(src).match(new RegExp(`isIn\\(${name}\\)`, 'g')) || []).length;

describe('schema enum 就是常量本身', () => {
  test('Permission 的三个 enum 逐组等于 constants/permission.js（顺序也一致）', () => {
    expect(Permission.schema.path('type').enumValues).toEqual(PERMISSION_TYPES);
    expect(Permission.schema.path('method').enumValues).toEqual(PERMISSION_METHODS);
    expect(Permission.schema.path('status').enumValues).toEqual(RESOURCE_STATUSES);
  });

  test('Role.status 与 Permission.status 共用同一份常量，而不是两份同内容副本', () => {
    expect(Role.schema.path('status').enumValues).toEqual(RESOURCE_STATUSES);
    expect(Permission.schema.path('status').enumValues).toEqual(RESOURCE_STATUSES);
    // 内容 equal 证明不了同源（有人把 Role 改回字面量时值照样相等、这条仍绿），
    // 所以这里对账的是**写法**：两个 model 都必须把 enum 指向常量名。
    expect(codeOnly(read('src/models/Role.js'))).toContain('enum: RESOURCE_STATUSES');
    expect(codeOnly(read('src/models/Permission.js'))).toContain('enum: RESOURCE_STATUSES');
  });

  test('User.status 就是 Object.values(USER_STATUS)（权威清单在 utils/constants.js）', () => {
    expect(User.schema.path('status').enumValues).toEqual(Object.values(USER_STATUS));
    expect(new Set(User.schema.path('status').enumValues).size).toBe(
      Object.keys(USER_STATUS).length
    );
  });
});

describe('引用点数量对账：原副本位置必须都已改成引用', () => {
  // 期望数量 = 重接线前 grep 实测的字面量处数，不是凭印象写的
  const ROUTE_SITES = [
    ['src/routes/permissionRoutes.js', 'PERMISSION_TYPES', 4],
    ['src/routes/permissionRoutes.js', 'PERMISSION_METHODS', 3],
    ['src/routes/permissionRoutes.js', 'RESOURCE_STATUSES', 2],
    ['src/routes/roleRoutes.js', 'RESOURCE_STATUSES', 1],
  ];
  for (const [file, name, n] of ROUTE_SITES) {
    test(`${file} 里 isIn(${name}) 恰好 ${n} 处`, () => {
      expect(isInCount(read(file), name)).toBe(n);
    });
  }

  test('roleGuards 通过重命名引用拿到同一份 status 清单（它用的是本地别名 ROLE_STATUSES）', () => {
    const src = codeOnly(read('src/controllers/roleGuards.js'));
    expect(src).toContain('RESOURCE_STATUSES: ROLE_STATUSES');
    expect(src).not.toContain("['active', 'inactive']");
    // 别名必须仍然被真的使用（否则等于把副本换成死变量）
    expect(src).toContain('ROLE_STATUSES.includes(status)');
    expect(src).toContain('ROLE_STATUSES,');
  });

  test('账户状态的两个消费点用允许清单（!== USER_STATUS.ACTIVE），不抄坏值清单', () => {
    // F-162：登录（authService.assertAccountUsable）与每请求认证（middleware/auth
    // .assertAccountUsable）原先各自把 'inactive'/'locked' 列一遍——同一概念在本仓有第三种
    // 答案（refresh 用 `!== 'active'`）。按枚举拒绝的后果：USER_STATUS 加一档、或裸写进一个
    // 清单外的值（备份还原）时，这两处**完整放行**而 refresh 拒绝。
    // 本文件原先的 files 清单不含这两处，所以门禁看不见它们——现在按写法对账。
    const gate = (f) => {
      const src = codeOnly(read(f));
      expect(src).toContain('!== USER_STATUS.ACTIVE');
      expect(src).toContain("require('../utils/constants')");
    };
    gate('src/services/authService.js');
    gate('src/middleware/auth.js');
    // 自证前提：字面量 'inactive' 在 authService 里仍然合法存在（锁定状态机 1195/1203 读它），
    // 所以本门禁判的是"可用性判据的写法"，不是"文件里不许出现这个词"。
    expect(codeOnly(read('src/services/authService.js'))).toContain("'inactive'");
    expect(codeOnly(read('src/middleware/auth.js'))).not.toContain("'inactive'");
  });

  test('8 个被改写的文件里不得再出现这四组值的字面量副本', () => {
    const LITERALS = [
      "'menu', 'button', 'api', 'data'",
      "'GET', 'POST', 'PUT', 'DELETE', 'PATCH', '*'",
      "'active', 'inactive'",
      "'active', 'inactive', 'locked'",
    ];
    const files = [
      'src/models/Permission.js',
      'src/models/Role.js',
      'src/models/User.js',
      'src/routes/permissionRoutes.js',
      'src/routes/roleRoutes.js',
      'src/routes/userRoutes.js',
      'src/controllers/roleGuards.js',
      'src/services/userService.js',
    ];
    const hits = [];
    for (const f of files) {
      const src = codeOnly(read(f));
      for (const lit of LITERALS) if (src.includes(lit)) hits.push(`${f} <- ${lit}`);
    }
    expect(hits).toEqual([]);
    // 自证前提（缺了它上面那条就是死用例）：四组搜索串各自都必须"可被命中"，
    // 且必须**仍然等于权威清单当前的样子**。上一版这里写的是
    // `expect(\`enum: [${LITERALS[2]}]\`.includes(LITERALS[2])).toBe(true)`——
    // 字符串包含它自己，恒真且不读任何源码，是装饰不是对照（批次 65b 已证其不会红）。
    const quoted = (vals) => vals.map((v) => `'${v}'`).join(', ');
    // ① 运行时反推：任何一组清单加档/删档/换序，这条立刻红，逼着同步搜索串
    expect([
      quoted(PERMISSION_TYPES),
      quoted(PERMISSION_METHODS),
      quoted(RESOURCE_STATUSES),
      quoted(Object.values(USER_STATUS)),
    ]).toEqual(LITERALS);
    // ② 文本可命中性：前三组在 constants/permission.js 里就是数组字面量原文，
    // `String.includes` 这条路被证明真的能抓到（否则 ① 绿而 ② 失效也测不出来）
    expect(codeOnly(read('src/constants/permission.js'))).toContain(LITERALS[0]);
    expect(codeOnly(read('src/constants/permission.js'))).toContain(LITERALS[1]);
    expect(codeOnly(read('src/constants/permission.js'))).toContain(LITERALS[2]); // RESOURCE_STATUSES
    // LITERALS[3] 现在全仓没有合法宿主（USER_STATUS 是对象形态，第 8 处私抄已在批次 66
    // 接回 Object.values(USER_STATUS)）。它的可命中性由 ① 反推担保：搜索串就是
    // "手抄这份清单会写出来的样子"，谁再手抄一次就必然逐字命中。
    expect(codeOnly(read('src/routes/userRoutes.js'))).not.toContain(LITERALS[3]);
    expect(codeOnly(read('src/routes/userRoutes.js'))).toContain(
      'isIn(Object.values(USER_STATUS))'
    );
  });
});

describe('OpenAPI 生成器的枚举与运行时同源（文档不是运行时：没人对账就永不红）', () => {
  const generator = require('../../docs/generate.js');

  const getParamEnum = (pathKey, method, name) => {
    const node = generator.paths[pathKey];
    const params = node && node[method] && node[method].parameters;
    expect(params).toBeDefined();
    const item = params.find((q) => q.name === name);
    expect(item).toBeDefined();
    return item.schema.enum;
  };

  test('GET /api/users 的 status 文档枚举等于 Object.values(USER_STATUS)', () => {
    expect(getParamEnum('/api/users', 'get', 'status')).toEqual(Object.values(USER_STATUS));
  });

  test('POST /api/permissions 的 type/method 文档枚举等于 constants/permission.js', () => {
    const props =
      generator.paths['/api/permissions'].post.requestBody.content[
        Object.keys(generator.paths['/api/permissions'].post.requestBody.content)[0]
      ].schema.properties;
    expect(props.type.enum).toEqual(PERMISSION_TYPES);
    expect(props.method.enum).toEqual(PERMISSION_METHODS);
  });
});

describe('F-141：IP 名单类型（同一族，含查询侧手写白名单这一最坏形状）', () => {
  const { IP_LIST_TYPES } = require('../../constants/ipList');
  const IPBlacklist = require('../../models/IPBlacklist');

  test('IPBlacklist 的 enum 就是 constants/ipList.js，生成器写的是引用而不是副本', () => {
    expect(IPBlacklist.schema.path('type').enumValues).toEqual(IP_LIST_TYPES);
    // 内容 equal 证明不了同源（改回字面量时值照样相等），所以对账写法：
    expect(codeOnly(read('src/models/IPBlacklist.js'))).toContain('enum: IP_LIST_TYPES');
    expect(codeOnly(read('src/docs/generate.js'))).toContain('enum: IP_LIST_TYPES');
  });

  test('securityRoutes 里两处 isIn(IP_LIST_TYPES)（query 与 body 各一）', () => {
    expect(isInCount(read('src/routes/securityRoutes.js'), 'IP_LIST_TYPES')).toBe(2);
  });

  test('查询侧过滤走 includes，不再手抄 `a || b` 成员判定', () => {
    const src = codeOnly(read('src/controllers/ipListController.js'));
    expect(src).toContain('IP_LIST_TYPES.includes(type)');
    // 这条才是本族的**最坏形状**：手写成员判定不认识新档位时不是 400，而是
    // 整条丢掉过滤条件 ⇒ 返回全量名单（与 F-138 的 userService 同构）。
    // 所以这里断的是"这条判定不存在了"，光看内容对账抓不到它。
    expect(src).not.toContain("type === 'black' || type === 'white'");
  });

  test('四个引用文件里不得再出现名单类型的字面量副本（正对照见 constants/ipList.js）', () => {
    const files = [
      'src/models/IPBlacklist.js',
      'src/controllers/ipListController.js',
      'src/routes/securityRoutes.js',
      'src/docs/generate.js',
    ];
    const hits = [];
    for (const f of files) if (codeOnly(read(f)).includes("'black', 'white'")) hits.push(f);
    expect(hits).toEqual([]);
    expect(codeOnly(read('src/constants/ipList.js'))).toContain("'black', 'white'");
  });
});

describe('F-138 的真实杀伤路径：schema 合法值被服务层静默丢掉过滤条件', () => {
  const userService = require('../../services/userService');

  test('User schema 承认的每一个 status，buildListQuery 都必须真的下推该条件', () => {
    // 本文件唯一一条行为级用例，也是"为什么副本有害"的直接证据：
    // 两侧各抄一份时，给 USER_STATUS 加一档会让服务层白名单不认识它 ⇒
    // `?status=<新档>` 通过路由校验（校验读的是 Object.values(USER_STATUS)）、
    // 却在下推 Mongo 前被整个丢弃 ⇒ 返回**全量用户**而不是 400。
    // 现在两侧同源，这条恒真；任何一侧被改回私有清单，它立刻变红。
    const enumValues = User.schema.path('status').enumValues;
    expect(enumValues.length).toBeGreaterThan(1);
    // 夹具口径注记：第二参数必须是 getDataScope 形状的对象。原先传裸字符串 'all'，
    // 旧实现对它既不命中 'all' 分支也不抛错，而是落进 default 臂给 query 塞一个
    // { _id: null }——本用例只断言 query.status，于是「范围参数根本是错的」这件事
    // 一直没被发现（假绿）。#12 起裸字符串会被 isDataScopeDenied 判为不可用并抛 403。
    return Promise.all(
      enumValues.map((status) => userService.buildListQuery({ status }, { type: 'all' }))
    ).then((results) => {
      enumValues.forEach((status, i) => {
        expect(results[i].query.status).toBe(status);
      });
    });
  });

  test('非法 status 仍被丢弃（钉住既有语义，防止顺手改成 400 造成对外行为变化）', () => {
    return userService.buildListQuery({ status: 'not-a-status' }, { type: 'all' }).then((r) => {
      expect(r.query.status).toBeUndefined();
      expect(Object.values(USER_STATUS)).not.toContain('not-a-status');
    });
  });
});
