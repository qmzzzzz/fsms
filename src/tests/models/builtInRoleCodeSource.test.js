'use strict';

/**
 * 内置角色编码的第二份真源：pre-save 自动标记名单 vs 种子角色 vs 权限映射键
 *
 * 三个地方各自写着"哪些编码是内置角色"，没有任何一条行为用例能把它们对齐：
 *
 * 1) `src/models/Role.js` 的 pre('save') 钩子里有一份局部常量 `builtInCodes`，
 *    命中就把 `isBuiltIn` 强行置真——**不看调用方传了什么**。而 `isBuiltIn` 是
 *    一组硬后果的开关：删除被 `Role.js` 自己的删除护栏拒（"内置角色不可删除"）、
 *    改名与改层级被 `roleGuards.js` 拒、按用户授权限时被 `rolePermissionController.js`
 *    当作内置角色走克隆分支。于是"用一个特定编码建角色"＝铸造一条不可删除、
 *    不可改名、层级冻结的记录，而这条编码名单与真正的种子名单（下一项）并不相等。
 *
 * 2) `src/services/initData.js` 的 `defaultRoles` 才是实际种入的内置角色，
 *    每条自己显式带 `isBuiltIn: true`，不依赖那份钩子名单。
 *
 * 3) 同文件的 `rolePermissionMap` 用**编码字符串作键**给出每个内置角色的权限集。
 *    它没有导出，只能从源码读。这一处和 `defaultRoles` 的编码之间必须是**一一对应**：
 *    `initRoles` 取权限时写的是 `rolePermissionMap[roleCode] || []`，键一旦对不上，
 *    该内置角色的期望权限集就变成**空集**；紧接着"内置角色每次启动对账并强制收敛"
 *    那段会算出 needsUpdate=true，于是**每次启动把该角色的权限全部清空**。
 *    这不是"少发几个权限"而是"整档角色被静默清零"，而且不会有任何报错。
 *
 * 判据强度按实测分档，不按"应该是什么样"：
 *   - 第 3 条钉**集合相等**（今天成立，且方向无争议：改任何一侧都会红）。
 *   - 第 1 条只钉"今天这组分叉被冻结"——见 KNOWN_LEGACY_MINT_CODES 的注释：
 *     把 ADMIN/USER 从钩子名单里删掉是**行为决策**（会连带打破依赖它的既有夹具），
 *     不由这条用例单方面替人拍板，所以这里钉的是"不许再多一个"，而不是"应当为 0"。
 *   - 可达性另开一条真库用例（第 4 条），把第 1 条从"读代码推出来的风险"变成实测事实。
 */

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const Role = require('../../models/Role');
const { defaultRoles } = require('../../services/initData');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const ROLE_SRC = path.join(REPO_ROOT, 'src', 'models', 'Role.js');
const INIT_SRC = path.join(REPO_ROOT, 'src', 'services', 'initData.js');

/** 与既有单源闸同一口径：先剥注释，否则注释里抄一份名单就能把判据喂绿 */
const stripComments = (code) => code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

const codeOnly = (file) => stripComments(fs.readFileSync(file, 'utf8'));

/** 合成样本与真实源码共用同一步预处理，避免"自证的是另一条路径" */
const codeLike = (text) => stripComments(text);

/** Role.js 里 pre('save') 那份局部名单（它是函数体内的 const，取不出 import，只能读源码） */
function hookBuiltInCodes(src) {
  const m = /const builtInCodes = \[([^\]]*)\]/.exec(src);
  if (!m) return null;
  return [...m[1].matchAll(/'([^']*)'/g)].map((x) => x[1]);
}

/** initData.js 里 rolePermissionMap 的键（该常量未导出） */
function permissionMapKeys(src) {
  const from = src.indexOf('const rolePermissionMap = {');
  if (from < 0) return null;
  const rest = src.slice(from);
  const end = rest.indexOf('\n};');
  if (end < 0) return null;
  const block = rest.slice(0, end);
  return [...block.matchAll(/^\s*([A-Z][A-Z0-9_]*)\s*:\s*\[/gm)].map((m) => m[1]);
}

/**
 * 钩子名单里"种子角色并没有"的那部分。今天实测＝ ['ADMIN','USER']：
 * 这两个编码从未被 defaultRoles 种入，却会被 pre-save 标成内置。
 *
 * 为什么不钉"必须为空"：删掉它们会打破既有夹具——
 * `src/tests/models/roleBuiltInDeleteGuard.test.js` 用 `code: 'USER'` 造一条内置角色
 * 来测删除护栏，`src/tests/utils/tails.test.js` 用 `code: 'ADMIN'` 造超管之外的第二角色，
 * `scripts/audit-probes/ws-session-bypass.cjs` 同理。也就是说这份更宽的名单已经被别处
 * 当成契约在用，收窄它需要一次带迁移判断的改动（真实库里可能真有历史 ADMIN/USER 行，
 * 保留标记才删不掉它们），方向由人拍板。
 *
 * 这条闸的牙在"再多一个"：把名单改成第四个编码而不同步这里 ⇒ 红。
 */
const KNOWN_LEGACY_MINT_CODES = ['ADMIN', 'USER'];

/**
 * 两条判据函数被"真实源码用例"和"反向对照用例"共用同一份实现，
 * 否则对照臂自证的是另一套逻辑，真判据被写坏也不会红。
 */

/**
 * 两份编码名单的不一致项（差集 + 任一侧的重复项），空数组即一致。
 * 重复项也算：`rolePermissionMap` 是对象字面量，同一个键写两遍是"后者静默覆盖前者"，
 * 光比集合会把它当成一致放过去。
 */
const inconsistencyOf = (a, b) => {
  const A = new Set(a);
  const B = new Set(b);
  const dups = (xs) => xs.filter((c, i) => xs.indexOf(c) !== i);
  return [
    ...a.filter((c) => !B.has(c)),
    ...b.filter((c) => !A.has(c)),
    ...dups(a),
    ...dups(b),
  ].sort();
};

/** 名单里落在允许集合之外的编码 */
const straysOf = (codes, allowed) => [...new Set(codes)].filter((c) => !allowed.has(c)).sort();

describe('内置角色编码的三处真源', () => {
  let roleSrc;
  let initSrc;
  let hookCodes;
  let mapKeys;
  let seededCodes;
  let seededBuiltInCodes;

  beforeAll(async () => {
    // 本文件的可达性用例要真库；连接由用例自己建立（与 src/tests/models 既有护栏用例同口径）
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    roleSrc = codeOnly(ROLE_SRC);
    initSrc = codeOnly(INIT_SRC);
    hookCodes = hookBuiltInCodes(roleSrc);
    mapKeys = permissionMapKeys(initSrc);
    seededCodes = defaultRoles.map((r) => r.code);
    seededBuiltInCodes = defaultRoles.filter((r) => r.isBuiltIn).map((r) => r.code);
    // 锚点被挪走时要在每条用例上明确红，而不是让 Set(null) 抛一个看不懂的 TypeError
    expect(hookCodes).not.toBeNull();
    expect(mapKeys).not.toBeNull();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('提取器自证：合成脏样本抓得到、注释里的不算、锚点没被挪走', () => {
    // 判据靠源码解析 ⇒ 先证明解析器有牙，否则三处真源全被"读不到"骗成绿。
    // 合成样本走与真实源码**完全相同**的管道（剥注释 → 提取），否则自证的是另一条代码路径。
    expect(
      hookBuiltInCodes(codeLike("  const builtInCodes = ['SUPER_ADMIN', 'ZZ_FAKE_ONE'];"))
    ).toEqual(['SUPER_ADMIN', 'ZZ_FAKE_ONE']);
    expect(
      permissionMapKeys(
        codeLike('const rolePermissionMap = {\n  ZZ_FAKE_ONE: [\n  ZZ_FAKE_TWO: [\n};')
      )
    ).toEqual(['ZZ_FAKE_ONE', 'ZZ_FAKE_TWO']);

    // 注释里抄一份名单不算命中（本文件自己的注释就抄了 ADMIN/USER 这些字样）
    expect(hookBuiltInCodes(codeLike('/* const builtInCodes = [] */'))).toBeNull();
    expect(
      permissionMapKeys(codeLike('/* const rolePermissionMap = {\n  NOPE: [\n}; */'))
    ).toBeNull();
    // 反向：真实源码里这两个锚点确实各只有一处定义
    expect(roleSrc.match(/const builtInCodes = \[/g) || []).toHaveLength(1);
    expect(initSrc.match(/const rolePermissionMap = \{/g) || []).toHaveLength(1);
  });

  test('rolePermissionMap 的键与 defaultRoles 的编码集合必须完全相等（否则启动即清空该角色权限）', () => {
    // 机理见文件头：键对不上 ⇒ permIdsFor 返回空集 ⇒ 内置角色的权限每启动被收敛成 0 条。
    // 判据与下面"反向闸"共用 inconsistencyOf，保证对照臂测的就是这条用例真正用的逻辑。
    expect(inconsistencyOf(mapKeys, seededCodes)).toEqual([]);
  });

  test('钩子名单只允许"种子编码 + 已登记的遗留编码"，且遗留那部分今天恰好就是那两个', () => {
    // 落在种子编码之外的部分必须**恰好**等于登记的那两个：多一个（新.magic 编码被自动置内置）
    // 或少一个（收窄名单）都红。
    expect(straysOf(hookCodes, new Set(seededBuiltInCodes))).toEqual(
      [...KNOWN_LEGACY_MINT_CODES].sort()
    );

    // 今天实测的整组分叉再按**字面量**冻结一遍（不用"从同一份源码现算"的相对式，
    // 否则 initData 少标一条 isBuiltIn 会让两边同步变化而悄悄绿过去）：
    // 改任一侧都红，逼改动者把理由与迁移一起带来。
    expect(hookCodes.slice().sort()).toEqual(['ADMIN', 'SUPER_ADMIN', 'USER']);
    expect(seededBuiltInCodes.slice().sort()).toEqual([
      'FIREFIGHTER',
      'FIRE_SUPERVISOR',
      'GUEST',
      'SECURITY_ADMIN',
      'SUPER_ADMIN',
    ]);
    // 两名单唯一的交集必须是 SUPER_ADMIN——超管保护同时要求 code 与 isBuiltIn
    expect(hookCodes.filter((c) => seededBuiltInCodes.includes(c))).toEqual(['SUPER_ADMIN']);
  });

  test('反向闸：任一侧改名／重复键／只写在注释里，共用判据都必须转红', () => {
    // 上一节两条判据若被写空（例如"读不到就当中性"），删掉产品源码里的键不会红。
    // 这几条把"改名/重复/注释骗局"三种真实形态在内存里造出来，逐一对上失败签名。
    // 不碰产品文件：那两个文件另一条线正在改，矩阵留活体改动风险更大。

    // ① 只改一侧的编码名（最常见形态：重命名种子角色但忘了改权限映射）
    expect(
      inconsistencyOf(
        mapKeys.map((k) => (k === 'GUEST' ? 'GUEST_RENAMED' : k)),
        seededCodes
      )
    ).toEqual(['GUEST', 'GUEST_RENAMED']);

    // ② 对象字面量里同一个键写两遍：JS 语义是后者静默覆盖前者，集合比较会放过它
    expect(inconsistencyOf([...mapKeys, 'GUEST'], seededCodes)).toEqual(['GUEST']);

    // ③ 钩子名单多出一个编码 ⇒ 它既不是种子也不是登记过的遗留
    expect(straysOf([...hookCodes, 'ZZ_NEW_MINT'], new Set(seededBuiltInCodes))).toContain(
      'ZZ_NEW_MINT'
    );

    // ④ 骗局：真键改名 + 在注释里留原名。文本视图原名还在，剥注释后必须消失 ⇒ 判据仍红
    const dropped = initSrc.replace('\n  GUEST: [', '\n  // GUEST: [\n  GUEST_RENAMED: [');
    expect(dropped).not.toBe(initSrc); // 锚点还在（否则这条对照臂已经在自欺）
    expect(dropped).toContain('GUEST');
    expect(permissionMapKeys(codeLike(dropped))).not.toContain('GUEST');
    expect(inconsistencyOf(permissionMapKeys(codeLike(dropped)), seededCodes)).toEqual(
      expect.arrayContaining(['GUEST', 'GUEST_RENAMED'])
    );
  });

  test('可达性实测：用遗留编码建角色即被 pre-save 标成内置且删不掉，对照编码正常可删', async () => {
    // 真库用例（内存 MongoDB），证明上一节的分叉不是纸面风险：走公开 create 就能铸造
    const stamp = `${Date.now()}${Math.floor(Math.random() * 1000)}`;

    // code 上有唯一索引，且内存库是全 worker 共享的：别的套件可能已经建过 ADMIN。
    // 先复用、再兜住并发插入撞到的 11000，两种情况下判据都一样。
    const dup = (err) => Boolean(err) && err.code === 11000;
    let minted = await Role.findOne({ code: 'ADMIN' }).lean();
    let createdHere = false;
    if (!minted) {
      try {
        minted = (
          await Role.create({ name: `zz铸造${stamp}`, code: 'ADMIN', level: 5 })
        ).toObject();
        createdHere = true;
      } catch (err) {
        if (!dup(err)) throw err;
        minted = await Role.findOne({ code: 'ADMIN' }).lean();
      }
    }
    expect(minted).toBeTruthy();
    expect(minted.isBuiltIn).toBe(true); // 调用方从未要求过 isBuiltIn
    await expect(Role.deleteOne({ _id: minted._id })).rejects.toThrow(/内置角色不可删除/);
    // 清理走原生驱动：ODM 的删除护栏对这条记录本身就生效，用 ODM 删不掉自己造的残留
    if (createdHere) {
      await mongoose.connection.collection('roles').deleteMany({ _id: minted._id });
    }

    // 对照臂：不在名单里的编码不会被标记，删除一路畅通 ⇒ 上一条红不是因为"什么都删不掉"
    const normal = await Role.create({
      name: `zz对照${stamp}`,
      code: `ZZ_NOT_BUILT_IN_${stamp}`,
      level: 5,
    });
    expect(normal.isBuiltIn).toBe(false);
    await expect(Role.deleteOne({ _id: normal._id })).resolves.toBeDefined();
    await expect(Role.countDocuments({ _id: normal._id })).resolves.toBe(0);
  });
});
