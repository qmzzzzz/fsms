/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：src 里所有 User 模型的载入语句（本闸不执行任何业务代码，纯静态分类）
 * 守护的不变式：不存在"投影缺失的 读-改-save"——凡是把 User 文档载进内存再 .save()
 *   的语句，必须自己带上排除投影（models/User.js 的 unselectedCredentialProjection），
 *   否则 Mongoose 会给**本次根本没从服务器取回**的 select:false 路径填 schema 默认值，
 *   并把它们写进 save 的 $set（实测：一次改头像抹掉 mfaSecret/mfaRecoveryCodes/
 *   mfaFailCount/phoneKey/passwordHistory/mfaLastCounter）。
 * 可证伪性：见文件末「变异实测」——合成"裸载入+save"必被抓；去掉 .select( 后同一站点必须
 *   不被抓；把某处 .select(...) 删掉，第 2 组第 3 条的登记基数立刻不匹配。
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 为什么用静态闸而不是运行时钩子（想清楚再写，别下次又重新推导一遍）：
 *   pre('save') 里没法区分"默认值被误写回"与"业务显式写成默认值"——解绑 MFA 写的就是
 *   mfaSecret:''、重置口令历史写的就是 passwordHistory:[]，两者在 delta 里形状完全一样。
 *   所以这一族只能靠"载入端有没有带投影"这个可静态观测的事实来管。
 *
 * 站点身份用 **文件 + 归一化语句文本**，不用行号：本闸的输入是代码行而不是注释锚，
 * 任何一次上方插行都会让行号台账天天红；文本漂移会红，但只在"语句真的改了"时红。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const SRC = path.join(ROOT, 'src');

const LOAD_RE = /\bUser\.(findById|findOne)\s*\(/;
const SAVE_RE = /\.\s*save\s*\(/;

const isCommentLine = (line) => {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('/* ');
};

/**
 * 判据只能读代码，不能读散文。userController.js 的注释里就写着
 * "原子更新替代读-改-save：user.save() 会把整个文档回写" —— 不剥注释时，
 * 这句话本身就能让"该调用方会把文档存回去"判成成立（实测：去掉 saveUser(x) 那一臂后
 * 规则腿仍然绿，原因就在这行注释上）。行尾注释仍会漏进来，这是本闸承认的近似。
 */
const codeText = (lines) => lines.map((l) => (isCommentLine(l) ? '' : l)).join('\n');

const walkJs = (dir, out = []) => {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walkJs(p, out);
    else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
};

/** 载入语句所在文件的相对路径 + 语句文本（自身行 + 后续最多 3 行，直到分号） */
const statementOf = (lines, idx) => {
  const parts = [];
  for (let i = idx; i < Math.min(idx + 4, lines.length); i += 1) {
    parts.push(lines[i].trim());
    if (lines[i].includes(';')) break;
  }
  return parts.join(' ').replace(/\s+/g, ' ');
};

/**
 * 分类器：返回 { bare, wired }，元素为 { rel, text, saving }。
 * `saving` = 该载入语句之后 SAVE_WINDOW 行内出现 .save()——这是**近似**，
 * 所以清单里既有真站点也有"查重用完就丢"的近似假阳性；两种都必须登记，
 * 假阳性登记的理由就是它为什么不是缺陷（不写理由就等于把判据降级成"数字对上了"）。
 */
const SAVE_WINDOW = 25;
function classify(files) {
  const bare = [];
  const wired = [];
  for (const f of files) {
    const rel = path.relative(ROOT, f).replace(/\\/g, '/');
    const lines = fs.readFileSync(f, 'utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      if (isCommentLine(line)) return;
      if (!LOAD_RE.test(line)) return;
      const text = statementOf(lines, i);
      const hasSelect = /\.select\s*\(/.test(text);
      const saving = SAVE_RE.test(codeText(lines.slice(i + 1, i + 1 + SAVE_WINDOW)));
      (hasSelect ? wired : bare).push({ rel, text, saving });
    });
  }
  return { bare, wired };
}

const sourceFiles = () =>
  walkJs(SRC).filter((f) => !/^[\\/]?src[\\/]tests[\\/]/.test(path.relative(ROOT, f)));

const BARE_SAVING = () => classify(sourceFiles()).bare.filter((x) => x.saving);
const WIRED = () => classify(sourceFiles()).wired;

/**
 * 登记的"裸载入 + 近处有 save"例外集。
 * 两条都不是缺陷，判据是"载进来的文档只用来判存在性，从不 .save()"——
 * 各自的证据写在 reason 里，由下面第 2 组逐条复核（不是登记了就免检）。
 */
const EXEMPT = [
  {
    rel: 'src/services/authService.js',
    contains: 'User.findOne({ email: emailKey })',
    reason:
      '邮箱查重：结果只用于 if (existingUser) 判存在，文档不落地；save 的是另一个变量 user（已带排除投影）',
    recheck: (t) => /emailKey/.test(t),
  },
  {
    rel: 'src/services/userService.js',
    contains: 'User.findOne(filter)',
    reason:
      'findOneUser 是查重入口：两处调用方（userController 建号判重 / emailTakenBySomeoneElse）都只取 Boolean，从不 save 这个文档',
    recheck: (t) => /findOne\(filter\)/.test(t),
  },
];

describe('第 1 组 · 采集器有牙（判据不能静默返回空）', () => {
  test('合成"裸载入 + save"必须被分类为 bare&saving', () => {
    const synthetic = [
      '  const user = await User.findById(id);',
      '  user.avatar = x;',
      '  await user.save();',
    ];
    const text = statementOf(synthetic, 0);
    const hasSelect = /\.select\s*\(/.test(text);
    const saving = SAVE_RE.test(synthetic.slice(1).join('\n'));
    expect({ hasSelect, saving }).toEqual({ hasSelect: false, saving: true });
  });

  test('同一站点补上 .select(...) 后必须不再被算作裸载入（否则例外登记永远追不上）', () => {
    const synthetic = [
      '  const user = await User.findById(id).select(User.unselectedCredentialProjection());',
      '  await user.save();',
    ];
    const text = statementOf(synthetic, 0);
    expect(/\.select\s*\(/.test(text)).toBe(true);
  });

  test('注释行里的 User.findById 不算站点（散文不是代码）', () => {
    const synthetic = [
      '   * 它挡的是 HIGH 级"改头像顺手毁凭证"：`User.findById(id)` 不写投影时，...',
      '  await user.save();',
    ];
    expect(isCommentLine(synthetic[0])).toBe(true);
  });

  test('散文不是保存证据：注释里的 user.save() 不能让判据抬旗（这一条是被实测教训逼出来的）', () => {
    const prose = [
      '  // 原子更新替代读-改-save：user.save() 会把整个文档回写',
      '  await userService.saveUser(other);',
    ];
    // 同一份文本：剥注释后判"没保存"，不剥就判"保存了" —— 这正是 codeText 存在的理由
    expect(savesVar(codeText(prose), 'user')).toBe(false);
    expect(savesVar(prose.join('\n'), 'user')).toBe(true);
    expect(SAVE_RE.test(codeText(prose.slice(1)))).toBe(false);
    expect(SAVE_RE.test(prose.join('\n'))).toBe(true);
  });

  test('窗口不是无限大：SAVE_WINDOW 必须是有限正数（近似分类的自限）', () => {
    expect(Number.isInteger(SAVE_WINDOW)).toBe(true);
    expect(SAVE_WINDOW).toBeGreaterThan(0);
    expect(SAVE_WINDOW).toBeLessThanOrEqual(40);
  });
});

describe('第 2 组 · 真实站点的基数台账', () => {
  test('裸载入且近处有 save 的站点集合与登记例外逐字相等（新增必须有人登记，删了不许留空条目）', () => {
    const found = BARE_SAVING();
    const keys = found.map((x) => `${x.rel}::${x.text}`).sort();
    const registered = EXEMPT.map(
      (e) =>
        `${e.rel}::${found.find((x) => x.rel === e.rel && x.text.includes(e.contains))?.text ?? e.contains}`
    ).sort();
    expect(keys).toEqual(registered);
    expect(keys.length).toBe(EXEMPT.length);
  });

  test('每条登记例外当场复核：语句里确实没有把它自己 save 掉的动作', () => {
    const found = BARE_SAVING();
    expect(found.length).toBeGreaterThanOrEqual(1);
    for (const e of EXEMPT) {
      const hit = found.find((x) => x.rel === e.rel && x.text.includes(e.contains));
      expect(hit && e.recheck(hit.text)).toBe(true);
      // 复核判据：登记的那条语句本身不得包含 save（"save 在别处"由 reason 文字负责解释）
      expect(/\.save\s*\(/.test(hit.text)).toBe(false);
    }
  });

  test('已带投影的载入站点恰好 4 处，且每一处都排的是同一份派生投影（不许各写各的清单）', () => {
    const wired = WIRED().filter((x) => x.text.includes('unselectedCredentialProjection'));
    expect(wired.length).toBe(4);
    const sites = wired.map((x) => x.rel).sort();
    expect(sites).toEqual([
      'src/services/authService.js',
      'src/services/authService.js',
      'src/services/roleService.js',
      'src/services/userService.js',
    ]);
  });

  test('反查：四处已带投影的站点若去掉投影，本闸的分类立刻将它们记为裸载入（判据不是装饰）', () => {
    const wired = WIRED().filter((x) => x.text.includes('unselectedCredentialProjection'));
    const stripped = wired.map((x) => ({
      ...x,
      text: x.text.replace(/\.select\s*\([^)]*\)\s*\(?[^;]*\)?;/, ';'),
    }));
    for (const s of stripped) {
      expect(/\.select\s*\(/.test(s.text)).toBe(false);
    }
  });
});

/**
 * ── 文档外逃（跨文件闭合）────────────────────────────────────────────────
 * 行窗口判据有一类天生的盲区：`return User.findById(id)` 这种 helper 把文档交给
 * **另一个文件**的调用方，save 发生在调用方，本文件的窗口永远看不见。
 * roleService.findUserForUpdate 正是这个形状（它的名字承诺写回，却裸着载入）。
 * 所以这一族用"函数名 → 调用方接收变量 → 该调用方是否把这个变量存回去"来闭合，
 * 判据是身份而不是行距。
 */
const ESCAPE_RE = /^\s*return\s+User\.(findById|findOne)\s*\(/;
const DEF_HEAD_RE = (name) =>
  new RegExp(String.raw`^\s{2,4}(?:async\s+)?${name}\s*\([^()]*\)\s*\{\s*$`);
const ENC_METHOD_RE = /^\s{2,4}(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^()]*\)\s*\{\s*$/;
const ENC_FUNC_RE = /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/;
const RECV_RE = /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+/;

/** 接收变量是否在该文件里被存回文档：`x.save()` 与 `saveUser(x)`（包装写法同样致命） */
const savesVar = (fileText, recv) =>
  new RegExp(String.raw`\b${recv}(?:\.|\?\.)save\s*\(`).test(fileText) ||
  new RegExp(String.raw`\bsave[A-Za-z_$]*\(\s*${recv}\b`).test(fileText);

function escapingHelpers() {
  const out = [];
  for (const f of sourceFiles()) {
    const rel = path.relative(ROOT, f).replace(/\\/g, '/');
    const lines = fs.readFileSync(f, 'utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      if (isCommentLine(line) || !ESCAPE_RE.test(line)) return;
      const text = statementOf(lines, i);
      let name = null;
      for (let k = i - 1; k >= 0; k -= 1) {
        if (isCommentLine(lines[k])) continue;
        const m = ENC_METHOD_RE.exec(lines[k]) || ENC_FUNC_RE.exec(lines[k]);
        if (m) {
          name = m[1];
          break;
        }
      }
      out.push({ rel, name, line: i + 1, text, wired: /\.select\s*\(/.test(text) });
    });
  }
  return out;
}

/** 名字为 name 的 helper 的全部调用方（跨 src；定义行按形状剔除，不按名字剔） */
function consumersOf(name, selfFile, selfLine) {
  const hits = [];
  for (const f of sourceFiles()) {
    const rel = path.relative(ROOT, f).replace(/\\/g, '/');
    const lines = fs.readFileSync(f, 'utf8').split(/\r?\n/);
    const fileCode = codeText(lines);
    lines.forEach((line, i) => {
      if (isCommentLine(line)) return;
      if (!new RegExp(String.raw`\b${name}\s*\(`).test(line)) return;
      if (rel === selfFile && i + 1 === selfLine) return;
      if (DEF_HEAD_RE(name).test(line)) return;
      const recv = RECV_RE.exec(line);
      hits.push({
        rel,
        line: i + 1,
        recv: recv ? recv[1] : null,
        saving: recv ? savesVar(fileCode, recv[1]) : false,
      });
    });
  }
  return hits;
}

describe('第 3 组 · 文档外逃的跨文件闭合（行窗口看不见的那一类）', () => {
  test('保存识别器认得两种写法：x.save() 与 saveUser(x)（后者是 userController 的真实形态）', () => {
    expect(savesVar('  await user.save();', 'user')).toBe(true);
    expect(savesVar('  await userService.saveUser(user);', 'user')).toBe(true);
    expect(savesVar('  await userService.saveUser(other);', 'user')).toBe(false);
    expect(savesVar('  if (!user) return;', 'user')).toBe(false);
  });

  test('外逃 helper 的集合与登记逐字相等（新增一个 return User.find* 必须进来交代）', () => {
    const helpers = escapingHelpers();
    const registered = helpers
      .map((h) => `${h.rel}::${h.name}::${h.wired ? 'wired' : 'bare'}`)
      .sort();
    // 两边都排：默认 sort 按 UTF-16 码元，'findOneUser' 排在 'findUserForUpdate' 之前（'O' < 'e'）
    expect(registered).toEqual(
      [
        'src/services/roleService.js::findUserForUpdate::wired',
        'src/services/userService.js::findUserForUpdate::wired',
        'src/services/userService.js::findOneUser::bare',
      ]
        .slice()
        .sort()
    );
  });

  test('调用方枚举不是空转：三个 helper 的调用点基数逐字相等', () => {
    const helpers = escapingHelpers();
    expect(helpers.length).toBe(3);
    const per = helpers.map(
      (h) =>
        `${h.name}@${h.rel}:${h.wired ? 'wired' : 'bare'}=>${consumersOf(h.name, h.rel, h.line).length}`
    );
    // findUserForUpdate 同名两份定义互相计入调用方（保守：按形状剔除定义行，不按名字剔），
    // 于是它的调用点 = rolePermissionController 1 + userController 3 = 4；findOneUser = 2
    expect(per.sort()).toEqual(
      [
        'findUserForUpdate@src/services/roleService.js:wired=>4',
        'findUserForUpdate@src/services/userService.js:wired=>4',
        'findOneUser@src/services/userService.js:bare=>2',
      ].sort()
    );
  });

  test('规则：有"保存型调用方"的外逃 helper 必须自带排除投影；裸着的那一个必须零个保存型调用方', () => {
    const bareOnes = [];
    for (const h of escapingHelpers()) {
      const saving = consumersOf(h.name, h.rel, h.line).filter((c) => c.saving);
      if (h.wired) {
        // 判据要有牙：findUserForUpdate 确实存在把文档存回去的调用方（userController 的 saveUser(user)）
        expect(saving.length).toBeGreaterThanOrEqual(1);
      } else {
        expect(saving).toEqual([]);
        bareOnes.push(`${h.rel}::${h.name}`);
      }
    }
    expect(bareOnes).toEqual(['src/services/userService.js::findOneUser']);
  });
});

describe('第 4 组 · 缺陷面的边界：只有 User 有 select:false 路径', () => {
  test('全模型精确普查：有 select:false 路径的模型恰为 User 一个，且路径 8 条', () => {
    const modelDir = path.join(SRC, 'models');
    const offenders = [];
    for (const name of fs.readdirSync(modelDir)) {
      if (!name.endsWith('.js') || name === 'index.js') continue;
      let M;
      try {
        M = require(path.join(modelDir, name));
      } catch (e) {
        continue;
      }
      const schema = M && M.schema;
      if (!schema || !schema.paths) continue;
      const bad = Object.entries(schema.paths)
        .filter(([, p]) => p && p.options && p.options.select === false)
        .map(([k]) => k);
      if (bad.length) offenders.push({ model: name, n: bad.length, paths: bad.sort() });
    }
    expect(offenders).toHaveLength(1);
    expect(offenders[0].model).toBe('User.js');
    expect(offenders[0].n).toBe(8);
    expect(offenders[0].paths).toEqual(
      [
        'mfaFailCount',
        'mfaLastCounter',
        'mfaLockUntil',
        'mfaRecoveryCodes',
        'mfaSecret',
        'password',
        'passwordHistory',
        'phoneKey',
      ].sort()
    );
  });

  test('派生投影与普查结果同源：helper 的键集合必须等于 schema 里 select:false 的路径集合', () => {
    const User = require(path.join(SRC, 'models/User'));
    const fromSchema = Object.entries(User.schema.paths)
      .filter(([, p]) => p && p.options && p.options.select === false)
      .map(([k]) => k)
      .sort();
    expect(Object.keys(User.unselectedCredentialProjection()).sort()).toEqual(fromSchema);
  });
});

/*
 * 变异实测（2026-10-03；跑法 node tools/ledger.js <被测文件> <本文件> <模式=预测>，
 * 12 趟变异每趟恢复后都与开始时的字节 sha 相同；基线 15 条腿全绿 ×5 次被测文件）
 *
 * 门禁自身退化（5 种，预测全部命中）
 *   ledger-everything-wired   预测红:#6,#7  实测红:#6,#7   —— 全记成"已带投影"后例外台账确实空转，#6/#7 抓到
 *   ledger-window-unbounded   预测红:#5,#6  实测红:#5,#6   —— 窗口放到全文件：自限腿 + 例外台账同时红
 *   ledger-consumers-blind    预测红:#12,#13 实测红:#12,#13 —— 调用方枚举退回空数组，基数腿与规则腿同时红
 *   ledger-save-detector-blind 预测红:#10,#13 实测红:#10,#13 —— 见下方"修过一轮"
 *   ledger-comment-blind      预测红:#4      实测红:#4      —— codeText 退化成不剥注释，只有 #4 抓到（说明其余判据此刻没在吃散文）
 *
 * 业务端删投影（5 种，预测命中 4 种 + 1 种形状意外）
 *   drop-profile-projection        预测红:#8     实测红:#8
 *   drop-lock-projection           预测红:#8     实测红:#8
 *   drop-findforupdate-projection  预测红:#6,#8,#11,#12,#13 实测同
 *   drop-role-findforupdate-projection 预测红:#8,#11,#12,#13 实测同 —— 这一颗今天不致命（调用方走
 *     findByIdAndUpdate），但第 3 组认得它的形状：延时雷被登记，不是被放过
 *   helper-select-true             预测红:#15    实测红:#15
 *   helper-to-string-form          预测"全绿"    实测红:#15  ← 脱靶 1 条，且是往好的方向脱：
 *     字符串形态下 Object.keys(返回串) 得到的是 '0','1',… 的索引，与 schema 路径集必然不等，
 *     静态闸因此也挡住了"把 helper 简化成一行字符串"。行为闸（userSaveCredentialWipe 第 0 组）
 *     从查询形状角度挡同一件事，两边不共享判据。
 *
 * 两处判据自纠（都由预测脱靶引出，不是先想到再补的）
 *   1) ledger-save-detector-blind 第一次只红 #10、不红 #13。查出的根因：savesVar 拿整份文件原文
 *      做正则，而 userController.js 里的**注释**就写着 `user.save()`（那句"原子更新
 *      替代读-改-save"的说明）——判据把散文当成了证据。修法=先 codeText 剥注释再判，
 *      并新增腿 #4 把这条教训钉成断言（同一段文本，剥注释判 false、不剥判 true）。
 *      残余近似：行尾注释 `foo(); // user.save()` 仍会漏进来，本闸承认这一点。
 *   2) drop-profile-projection 不会红 #6（窗口配对）。量出来的距离：authService 载入行、
 *      对应的 await user.save()（相距 41 行），setUserLockStatus 相距 59 行，
 *      都超出 SAVE_WINDOW=25。也就是说这两处的守护腿是 #8 的**基数台账**，#6 的窗口配对只负责
 *      "新站点必须进来登记"。跨文件的 save（userService.findUserForUpdate 交出去的文档由
 *      userController 的 saveUser(user) 落地）由第 3 组按身份闭合，不按行距闭合。
 */
