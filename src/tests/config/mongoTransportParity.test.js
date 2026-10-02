/**
 * 备份/恢复的容器传输与 URI 改写必须是同一份判据
 *
 * 两条真实缺陷都在这一类里：
 *  1. `backup-mongo.sh` 有 `local|docker` 传输开关（compose 里 mongo 只 expose，
 *     宿主机连不上），而 `restore-mongo.sh` 没有 ⇒ "数据级回滚抓手"要在真要用的那天
 *     才发现跑不通（README:344 / rollback-drill.md 都把它当回滚手段引用）。
 *  2. 两个脚本各自维护同一句 `sed -E "s#^((mongodb(\+srv)?://)([^/]*@)?)[^/]*#\1…#"`，
 *     且失败判据都是"替换后与原串相同 ⇒ 形态不认识"。这个判据有真假阳性：
 *     无凭据、主机本来就写成目标地址（在容器内跑脚本时正是这一形态）会被拒绝执行。
 *  3. 那句 sed 自身带着两个静默失效，所以改写现在是纯 shell 字符串重建：
 *     替换串里的字面 `\n` 被 GNU sed 展开成真换行（`MONGO_CONTAINER_HOST` 能给
 *     mongodump 的 0600 配置追加第二行），口令里未转义的 `/` 会终结 `[^/]*` 那次
 *     匹配 ⇒ 替换错位、凭据被静默丢弃（横幅却承诺原主机与原库名）。
 *  4. `mongo_validate_uri` 的"越界字节"判据原先写成 `$(… | tr -d '\041-\176')` 非空，
 *     而命令替换会剥掉**尾部**全部换行 ⇒ 只靠换行分隔的注入载荷（`…?authSource=admin\n
 *     drop:true`）判为空串放行。现在必须带哨兵字符再比。
 *  5. 上面这些是"取哪一段"的判据换掉之后**新能看见**的形态（逐条实测，判据原文见
 *     scripts/mongoUri.sh 头部）：`a@b@c`、`u:p@ss@h`、`u@p@h` 这类双 `@` 串，参考解析器
 *     **不报错**却把中间那段读成主机（静默改拨号对象）；`h:0`、`h:65536` 这类端口越界，
 *     解析器报错，而我们若放行就是"顺手把坏端口换成目标端口"。
 *  6. 一条与实现无关、却让整道闸看起来坏掉的夹具陷阱：jest-each 的行数组比测试函数声明的
 *     形参短时会把 `done` 注入成最后一个实参（bind.js:78-80）⇒ 那些行不是断言失败而是**超时**。
 * 行为判据用 `bash` 真跑 `mongoUri.sh`（不是断言源码含某串）；
 * 结构判据防止"把共享实现删掉、再各写一份"回潮。
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const HELPER = path.join(ROOT, 'scripts/mongoUri.sh');
const BACKUP = path.join(ROOT, 'scripts/backup-mongo.sh');
const RESTORE = path.join(ROOT, 'scripts/restore-mongo.sh');

const read = (p) => fs.readFileSync(p, 'utf8');

/**
 * shell 单引号转义：夹具里的 `$`、反引号、`"` 必须**原样**到达 shell。
 * 用双引号拼命令时，`MONGODB_URI='mongodb://u:p@h/db?authSource=$admin'` 这类
 * 载荷会被 bash 先展开一次，测到的就不是被测函数的行为了。
 */
const sq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const HELPER_POSIX = HELPER.replace(/\\/g, '/');

/** 真跑一次 URI 改写；bash 缺失时直接判红（不用 skip 制造假绿） */
function swapHost(uri, target) {
  const script = `. ${sq(HELPER_POSIX)}; out=$(mongo_swap_host ${sq(uri)} ${sq(target)}); echo "rc=$?|out=$out"`;
  const stdout = execFileSync('bash', ['-c', script], { encoding: 'utf8' });
  return stdout.trim();
}

/** 真跑一次值判据，把 stderr Reason 一起取回来（消息只含标签，不含 URI 内容） */
function validateUri(uri) {
  const script =
    `. ${sq(HELPER_POSIX)}; ` +
    `if msg=$(mongo_validate_uri ${sq(uri)} 标签 2>&1); then echo 'rc=0|msg='; ` +
    `else echo "rc=1|msg=$msg"; fi`;
  const stdout = execFileSync('bash', ['-c', script], { encoding: 'utf8' });
  return stdout.trim();
}

/**
 * 载荷由 shell 自己造（`uri=$(printf '…\r')`），而不是把裸控制字符塞进 `bash -c` 的命令串。
 * 实测差别：JS 字面量里的 CR 会在传输层被吃掉 ⇒ 函数收到的是"没有 CR 的串"，
 * 判据照样放行，测试却是绿的（假绿）。LF 没这个问题，所以只在 CR 那一臂用现场构造。
 */
function validateUriBuilt(payloadExpr) {
  const script =
    `. ${sq(HELPER_POSIX)}; uri=$(${payloadExpr}); ` +
    `if msg=$(mongo_validate_uri "$uri" 标签 2>&1); then echo 'rc=0|msg='; ` +
    `else echo "rc=1|msg=$msg"; fi`;
  return execFileSync('bash', ['-c', script], { encoding: 'utf8' }).trim();
}

/**
 * 真跑一个 helper，把判据细节钉在 helper 层：整条 URI 被拒时，运维看到的只有一句
 * "无法把 URI 主机段改写为容器内地址"，究竟是哪条判据点亮的只有直接问它才知道。
 */
function callHelper(fn, arg) {
  const script = `. ${sq(HELPER_POSIX)}; ${fn} ${sq(arg)}; echo "rc=$?"`;
  return execFileSync('bash', ['-c', script], { encoding: 'utf8' }).trim();
}

/**
 * 参考解析器的读法。
 *
 * 为什么必须问解析器而不是比字符串：`mongo_swap_host` 的产物会原样写进 mongodump 的
 * 0600 配置，唯一有意义的判据是"**实际被拨号的主机**是不是横幅承诺的那一个"。
 * 字符串相等证不了这件事——实测缺陷 1 的产物
 * `mongodb://u:p@db.internal:27017?appname=bob@127.0.0.1:27017` 在解析器里**不报错**，
 * 读出来是 hosts=["db.internal:27017"]：备份安静地连到宿主机名上，退出码却可以是 0。
 *
 * 取 `mongoose.mongo`（src/config/database.js:51 讨论的那份内嵌
 * mongodb-connection-string-url）而不是顶层包：本仓已实测过两份版本的行为不一致
 * （报错回显形态不同），而应用侧真正的消费点是 mongoose。`new MongoClient(uri)` 在
 * 构造期就解析连接串、不做任何 I/O（不 connect 就不留句柄）。
 * 已知边界：`mongodb+srv://` 的种子列表要等 SRV 查询，解析期 `hosts` 是空数组，
 * 所以 +srv 那一臂由真值表的端口判据钉，不进这里的逐行比较。
 */
const { MongoClient } = require('mongoose').mongo;

/** 参考解析器给每个主机补默认端口 27017，所以 `mongo` 与 `mongo:27017` 是同一个读法 */
function normalizeTarget(t) {
  if (t.startsWith('[')) return /:\d+$/.test(t) ? t : `${t.slice(0, t.indexOf(']') + 1)}:27017`;
  return t.includes(':') ? t : `${t}:27017`;
}

/** 解析结果里与"主机段改写"有关的事实；解析失败 ⇒ {ok:false, why} */
function parseUri(uri) {
  try {
    const o = new MongoClient(uri).s.options;
    return {
      ok: true,
      hosts: o.hosts.map((h) => (h.isIPv6 ? `[${h.host}]` : h.host) + (h.port ? `:${h.port}` : '')),
      db: o.dbName ?? null,
      creds: o.credentials ? `${o.credentials.username}:${o.credentials.password ?? ''}` : null,
    };
  } catch (e) {
    return { ok: false, why: e.message };
  }
}

/**
 * 纯函数：一次改写的产物相对输入改了哪些"不该改的东西"。返回违规说明数组。
 * 抽出来是为了能被合成违例（旧缺陷的真实产物）直接攻击——见「判据有牙」那条。
 * 凭据字段是夹具里的假值（真凭据绝不进这些夹具），所以失败时让它进 jest diff，
 * 换取"u:p%40ss 有没有被解成 u:p@ss"这类断言真的可比。
 */
function parityViolations({ input, output, target }) {
  const a = parseUri(input);
  const b = parseUri(output);
  if (!a.ok) {
    // 输入本来就解析不动：只有"故障被原样继承"才放行（我们没修好它，但也没换一个错）
    if (!b.ok && a.why === b.why) return null; // null ⇒ 这条属于"继承自输入"，由调用方登记
    if (!b.ok)
      return [`输入解析失败（${a.why}），产物换成了另一个错（${b.why}）：改写没修好任何东西`];
    return [
      `输入解析失败（${a.why}），产物却解析得动——改写凭空修好了输入，说明它动了凭据/主机之外的段`,
    ];
  }
  if (!b.ok) return [`产物解析失败（${b.why}）：改写凭空造出一个 mongodump 拒收的串`];
  const out = [];
  const want = [normalizeTarget(target)];
  if (JSON.stringify(b.hosts) !== JSON.stringify(want))
    out.push(`产物被读成 ${JSON.stringify(b.hosts)}，而横幅承诺 ${JSON.stringify(want)}`);
  if (b.db !== a.db) out.push(`库名从 ${JSON.stringify(a.db)} 变成 ${JSON.stringify(b.db)}`);
  if (b.creds !== a.creds)
    out.push(`凭据从 ${JSON.stringify(a.creds)} 变成 ${JSON.stringify(b.creds)}（只该动主机段）`);
  return out;
}

/**
 * jest-each 的表宽判据：测试函数声明的形参数不得超过最短那一行。
 * 短一行 ⇒ jest-each 把 `done` 追加成最后一个实参（bind.js:78-80）⇒ 30 秒超时。
 * 字符串表的每一行在 jest-each 内部也是 `row.arguments`，这里按数组长度处理即可。
 */
const fitsTable = (fn, rows) =>
  rows.length > 0 && rows.every((r) => fn.length <= (Array.isArray(r) ? r.length : 1));

describe('mongo_swap_host 行为真值表', () => {
  const T = '127.0.0.1:27017';
  const cases = [
    ['mongodb://u:p%40ss@mongo:27017/fsms', `rc=0|out=mongodb://u:p%40ss@${T}/fsms`],
    [
      'mongodb://u:p@mongo:27017/fsms?replicaSet=rs0&authSource=admin',
      `rc=0|out=mongodb://u:p@${T}/fsms?replicaSet=rs0&authSource=admin`,
    ],
    // 缺陷 5（判据原文见 scripts/mongoUri.sh 头部）：`+srv` 形态禁止端口，而容器内地址按
    // 实际部署必然带端口（默认 127.0.0.1:27017）。旧写法照样改写并交出
    // `mongodb+srv://u:p@127.0.0.1:27017/fsms`——mongodump 直接拒
    // （'mongodb+srv URI cannot have port number'）。目标不带端口时照旧放行，
    // 见 badTargets 之后那条反向自证。
    [`mongodb+srv://u:p@cluster0.example.net/fsms`, 'rc=1|out='],
    // 假阳性回归点：主机段已经就是目标地址 ⇒ 合法空操作，不得拒绝
    [`mongodb://${T}/fsms`, `rc=0|out=mongodb://${T}/fsms`],
    ['mongodb://mongo:27017', `rc=0|out=mongodb://${T}`],
    ['not-a-uri', 'rc=1|out='],
    ['mongodb://', 'rc=1|out='],
    // 切出来的主机段必须"确实是一个 authority"，否则整次重建都是在猜
    ['mongodb://u:p/x@h:27017/db', 'rc=1|out='],
    ['mongodb://u:p@mongo:abc/fsms', 'rc=1|out='],
    ['mongodb://u:p@mongo:/fsms', 'rc=1|out='],
    ['mongodb://u:p@[::1]:abc/db', 'rc=1|out='],
    // IPv6 字面量：方括号内不做字符集判据，只判括号外的端口
    ['mongodb://[::1]:27017/db', `rc=0|out=mongodb://${T}/db`],
    ['mongodb://u:p@[::1]/db', `rc=0|out=mongodb://u:p@${T}/db`],
    // 库名里的裸 `@`：**带凭据**时它不参与主机段提取（authority 终止于第一个 `/`，
    // userinfo 的分界已在第一个 `@` 处用掉），必须放行；**不带凭据**时解析器把它当成
    // userinfo 分隔符吃掉主机段（`mongodb://h:27017/db@x` ⇒ password=`27017/db` ⇒
    // 'Password contains unescaped characters'），输入本身就无效 ⇒ 点名拒绝。
    // 上一版把这两种形态写成了一条"尾部含 @ 一律放行"，于是交回一个 mongodump 认不出的串。
    ['mongodb://h/db@x', 'rc=1|out='],
    ['mongodb://h:27017/db@x', 'rc=1|out='],
    ['mongodb://h/db@x?authSource=admin', 'rc=1|out='],
    ['mongodb://u:p@mongo/db@name', `rc=0|out=mongodb://u:p@${T}/db@name`],
    ['mongodb://u:p@mongo:27017/db@name', `rc=0|out=mongodb://u:p@${T}/db@name`],
    // `#` 家族（**负结果**，取证见下面那条专门测试）：第一版把 `mongodb://h#1/db` 写成
    // "解析器读成 ["h#1"]、我们比它严"，实测不成立——参考解析器同样在 `#` 处终止
    // authority（读成 hosts=["h:27017"]、db="db"），与本文件 `${_rest%%[/?#]*}` 同一口径。
    // 所以这一形态放行，产物由逐行 parity 闸比对；不要因为它"看着怪"再加一条拒绝。
    ['mongodb://h#1/db', `rc=0|out=mongodb://${T}#1/db`],
    // 同族：库名里的裸 `#` 被解析器当片段起点截成 `my`（正确写法是 `%23`）。
    // 那是它自身的规则、改写前就在，尾部原样保留 ⇒ 两侧读法一致，不是我们造成的差异。
    ['mongodb://u:p@h/my#db', `rc=0|out=mongodb://u:p@${T}/my#db`],
    // 值判据必须覆盖**两条**出口：改写那支已接，合法空操作那支也必须接。
    // 空操作那支少了这一步，"主机本来就等于目标地址"的 URI 就绕过全部检查被原样
    // 交回调用方，而调用方紧接着把它写进 mongodump 的 0600 配置（`\ndrop:true` 成为第二行）。
    [`mongodb://${T}/fsms\ndrop:true`, 'rc=1|out='],
    ['mongodb://u:p@mongo:27017/fsms\ndrop:true', 'rc=1|out='],
    // 成对的反向自证：同一载荷换成合法的查询串写法（无换行）必须放行，
    // 否则上面两条可能只是"任何带 drop 字样的串都拒"这种假严格
    [`mongodb://${T}/fsms?drop:true`, `rc=0|out=mongodb://${T}/fsms?drop:true`],

    // ── 2026-10-03 实测的取段缺陷五条（判据原文见 scripts/mongoUri.sh 头部注释）────────
    // 缺陷 1（最严重的一条）：`case */* | \?* | *` 的第三分支在"无路径但有查询串"时
    // 把整串（含查询串）当成 authority，再用 `##*@`（**最后**一个 `@`）切凭据 ⇒ 主机段
    // 变成 `corp`。实测产物 `mongodb://u:p@db.internal:27017?appname=bob@127.0.0.1:27017`
    // 且 rc=0：主机段没动、目标地址被拼进查询串，而参考解析器把它读成
    // hosts=["db.internal:27017"]（**不报错**，见下面「产物必须被读成承诺的主机」的
    // 合成违例那条）——横幅承诺 127.0.0.1，mongodump 连的是 db.internal。
    [
      'mongodb://u:p@db.internal:27017?appname=bob@corp',
      `rc=0|out=mongodb://u:p@${T}?appname=bob@corp`,
    ],
    // 缺陷 2/3：副本集种子列表与"无路径带查询"都是合法形态，旧写法按单主机 +
    // 不含逗号的字符集判据把它们一起拒了——备份不了合法 URI，报的却是"形态异常"。
    ['mongodb://a:27017,b:27017/db?replicaSet=rs0', `rc=0|out=mongodb://${T}/db?replicaSet=rs0`],
    ['mongodb://u:p@h:27017,ii:27018/db', `rc=0|out=mongodb://u:p@${T}/db`],
    ['mongodb://h:27017?directConnection=true', `rc=0|out=mongodb://${T}?directConnection=true`],
    // 缺陷 4 的另一半：多个 `@` 的 authority 按**第一个**分界切，切完主机段里还剩 `@`
    // 就是形态不认识（解析器对它报 'Invalid connection string'）。
    ['mongodb://a@b@c:27017/db', 'rc=1|out='],
    // 空 userinfo 段：解析器直接拒（'URI contained empty userinfo section'），
    // 旧写法按"没有凭据"静默改写后返回 rc=0——交回一个 mongodump 认不出的串。
    ['mongodb://@h:27017/db', 'rc=1|out='],
    ['mongodb://:p@h:27017/db', 'rc=1|out='],
    // 种子列表的空项（首/尾/连续逗号）：解析器读成"少一个主机"，
    // 而"少一个种子"在备份脚本里正是现场看不出来的差异。
    ['mongodb://h:27017,/db', 'rc=1|out='],
    ['mongodb://,h:27017/db', 'rc=1|out='],
    ['mongodb://h:27017,,ii:27018/db', 'rc=1|out='],
    // 成对：真正的多主机列表必须放行（否则上面三条可能只是"任何带逗号的串都拒"）
    ['mongodb://h:27017,ii:27018/db', `rc=0|out=mongodb://${T}/db`],
    // 第二个冒号：`h:1:2` 解析器报 'Unable to parse h:1:2 with URL'
    ['mongodb://h:1:2/db', 'rc=1|out='],
    // 端口区间（参考解析器两条都**报错**，实测）：`h:0` ⇒ 'Invalid port (zero) with hostname'，
    // `h:65536` ⇒ 'Unable to parse h:65536 with URL'。放行它们的失效方向不是"响亮拒绝"，
    // 而是"顺手把坏端口换掉了"——产物解析得动，于是运维拿到一个从来不存在、
    // 也从来没被 mongodump 拒过的 URI（横幅却承诺原库名与原凭据）。
    ['mongodb://u:p@h:0/db', 'rc=1|out='],
    ['mongodb://u:p@h:65536/db', 'rc=1|out='],
    ['mongodb://u:p@h:70000/db', 'rc=1|out='],
    ['mongodb://u:p@[::1]:65536/db', 'rc=1|out='],
    // 成对反向自证：区间端点本身与"前导零"（解析器把 `07017` 读成 7017）必须放行，
    // 否则上面四条可能只是"端口写得长一点就一律拒"这种假严格
    ['mongodb://u:p@h:1/db', `rc=0|out=mongodb://u:p@${T}/db`],
    ['mongodb://u:p@h:65535/db', `rc=0|out=mongodb://u:p@${T}/db`],
    ['mongodb://u:p@h:07017/db', `rc=0|out=mongodb://u:p@${T}/db`],
    ['mongodb://u:p@[::1]:65535/db', `rc=0|out=mongodb://u:p@${T}/db`],
    // 方括号内做字符集判据：`[a b]` 这类越界字节不得先放行、再靠 mongodump 报一个
    // 和"主机段被改写"毫无关系的解析错。
    ['mongodb://u:p@[a b]:27017/db', 'rc=1|out='],
    ['mongodb://u:p@[::1]x:27017/db', 'rc=1|out='],
    // 空口令/无口令的 userinfo 是合法形态（解析器接受），不得被 userinfo 判据误杀
    ['mongodb://u:@h:27017/db', `rc=0|out=mongodb://u:@${T}/db`],
    ['mongodb://u@h:27017/db', `rc=0|out=mongodb://u@${T}/db`],
  ];
  test.each(cases)('%s', (uri, expected) => {
    expect(swapHost(uri, T)).toBe(expected);
  });

  // 目标地址即将被拼进连接串，而连接串原样写进 0600 配置文件：
  // 第一行是被否定的那条 sed 失效的真载荷（字面 `\n` 会被 GNU sed 展开成真换行，
  // 给 mongodump 的配置追加 `collection: auditLog` ⇒ 单集合导出记成"成功的全量备份"）。
  const badTargets = [
    [
      '字面 \\n（sed 展开成真换行）',
      'mongodb://u:p@mongo:27017/fsms',
      '127.0.0.1:27017\\ncollection:auditLog',
    ],
    ['真换行', 'mongodb://u:p@mongo:27017/fsms', '127.0.0.1:27017\ncollection:auditLog'],
    ['空格', 'mongodb://u:p@mongo:27017/fsms', 'bad host'],
    ['分号', 'mongodb://u:p@mongo:27017/fsms', 'a;b'],
    ['管道', 'mongodb://u:p@mongo:27017/fsms', 'a|b'],
    ['反引号', 'mongodb://u:p@mongo:27017/fsms', 'a`id`'],
    ['$（不得被展开）', 'mongodb://u:p@mongo:27017/fsms', 'a$b'],
    ['反斜杠', 'mongodb://u:p@mongo:27017/fsms', 'a\\b'],
    ['空串', 'mongodb://u:p@mongo:27017/fsms', ''],
  ];
  test.each(badTargets)('%s ⇒ 拒绝', (name, uri, target) => {
    expect(swapHost(uri, target)).toBe('rc=1|out=');
  });

  // ── 拒绝路径的可定位性（2026-10-03）─────────────────────────────────────────
  // 上面两张表只断言退出码与 stdout，**看不见 stderr**，而这一批改的正是 stderr：
  // 13 个互不相同的失效方向原先折叠成调用方那一句「请检查 MONGODB_URI 形态」，
  // `MONGO_CONTAINER_HOST` 为空或写错时同样 rc=1，运维却被告知去查 URI。
  // 所以这里把"拒绝必须能定位"钉成契约，而不是当成日志装饰——否则下次删掉
  // mongo_swap_refuse 的某一处调用，全表照绿。
  /** 真跑一次改写并把 stderr 取回（`swapHost` 刻意只看 stdout，不能复用） */
  function swapHostErr(uri, target) {
    const script =
      `. ${sq(HELPER_POSIX)}; ` +
      `err=$(mongo_swap_host ${sq(uri)} ${sq(target)} 2>&1 >/dev/null); rc=$?; ` +
      `printf 'RC=%s\\nERR=%s\\n' "$rc" "$err"`;
    const so = execFileSync('bash', ['-c', script], { encoding: 'utf8' });
    const at = so.indexOf('\nERR=');
    return { rc: Number(/RC=(-?\d+)/.exec(so)[1]), err: so.slice(at + 5).replace(/\n+$/, '') };
  }

  const uriRejects = cases.filter(([, e]) => e.startsWith('rc=1')).map(([u]) => u);
  const targetRejects = badTargets.map(([, uri, target]) => [uri, target]);

  test('每条拒绝都打一行 Error（只给退出码 ⇒ 现场无从定位）', () => {
    const all = [...uriRejects.map((u) => [u, T]), ...targetRejects];
    // 表要是被清空，下面所有断言会集体假绿，所以先把两条数据源的规模钉住
    expect(all.length).toBeGreaterThanOrEqual(25);
    for (const [uri, target] of all) {
      const { rc, err } = swapHostErr(uri, target);
      expect({ uri, rc }).toEqual({ uri, rc: 1 });
      expect({ uri, err }).toEqual({ uri, err: expect.stringContaining('Error:') });
      expect(err.length).toBeGreaterThan('Error:'.length);
    }
  });

  test('目标地址自身非法 ⇒ 必须点名 MONGO_CONTAINER_HOST（旧文案把它算到 URI 头上）', () => {
    // 这一条正是本批动机：URI 合法、目标非法时，旧的一句汇总让人去查 MONGODB_URI。
    for (const [uri, target] of targetRejects) {
      const { err } = swapHostErr(uri, target);
      expect({ target, err }).toEqual({
        target,
        err: expect.stringContaining('MONGO_CONTAINER_HOST'),
      });
    }
    // 反向自证：目标合法而 URI 非法时不得反过来冤枉 MONGO_CONTAINER_HOST。
    // 唯一豁免是 `+srv` 那条——它说的是"这个目标带端口，与 +srv 无解"，确实涉及目标。
    const uriFaulty = uriRejects.filter((u) => !u.startsWith('mongodb+srv'));
    expect(uriFaulty.length).toBeGreaterThanOrEqual(12);
    for (const uri of uriFaulty) {
      expect(swapHostErr(uri, T).err).not.toContain('MONGO_CONTAINER_HOST');
    }
  });

  test('原因是分了类的（一条通用文案过不了这条）', () => {
    const kinds = new Set([
      ...uriRejects.map((u) => swapHostErr(u, T).err),
      ...targetRejects.map(([, u, t]) => swapHostErr(u, t).err),
    ]);
    // 13 类判据折叠成一句通用文案 ⇒ size=1；随便两条相同 ⇒ 判据串档。
    // 这里取 8 而不是 13：种子列表空项 / 端口越界 / 方括号内越界字节同属
    // "主机段不是合法主机列表"一条文案，那是**有意的**（修法相同），不是漏分类。
    expect(kinds.size).toBeGreaterThanOrEqual(8);
    for (const k of kinds) expect(k.replace(/^Error:\s*/, '').trim().length).toBeGreaterThan(8);
  });

  test('拒绝文案只点类别，绝不回显 URI / 口令 / 目标地址的字节', () => {
    // 这是凭据：报错走 cron 邮件与 CI 日志，回显取值等于把口令抄进日志系统。
    // 三条载荷分别点亮**凭据段**、**主机列表**、**目标地址**三条出口，且每一段
    // 都放独特字节；任何一处 `echo "$_uri"` 漏进去都会被下面的 secret 清单点住。
    const probes = [
      ['mongodb://root:Sup3rPass@db.internal:27099,,/fsms', T],
      ['mongodb://root:Sup3rPass@@db.internal:27099/fsms', T],
      ['mongodb://root:Sup3rPass@db.internal:27099/fsms', 'bad host'],
      ['mongodb://root:Sup3rPass@db.internal:27099/fsms', '127.0.0.1:27017\ncollection:auditLog'],
    ];
    const secrets = [
      'Sup3rPass',
      'db.internal',
      '27099',
      'mongodb://',
      'collection:',
      'authSource',
    ];
    for (const [uri, target] of probes) {
      const { rc, err } = swapHostErr(uri, target);
      expect({ uri, rc }).toEqual({ uri, rc: 1 });
      expect(err).toContain('Error:');
      for (const secret of secrets) {
        expect({ uri, target, secret, err }).toEqual({
          uri,
          target,
          secret,
          err: expect.not.stringContaining(secret),
        });
      }
    }
  });

  test('少给一个参数是一条拒绝，不是把调用方打断（本文件被 set -u 的脚本 source）', () => {
    // 旧写法 `${1}`/`${2}` 在 set -u 下以 `unbound variable` 终结**整个调用方 shell**：
    // 门禁后面的清理与告警全部不执行，恢复脚本连"被拒绝"这件事都不会说出来。
    const script =
      `set -u; . ${sq(HELPER_POSIX)}; ` +
      `if mongo_swap_host 'mongodb://u:p@h:27017/db' 2>/dev/null; then echo branch=ok; ` +
      `else echo branch=refused; fi; echo alive=$?`;
    const so = execFileSync('bash', ['-c', script], { encoding: 'utf8' });
    // `alive` 必须还在 ⇒ 调用方没被带走；判据必须是拒绝而不是崩溃
    expect(so).toContain('branch=refused');
    expect(so).toContain('alive=');
    expect(so).not.toContain('unbound');
  });

  // 反向自证：上面九条不是"任意 target 都拒"——同一夹具换成合法 target 必须放行，
  // 否则判据已经退化成无条件失败，测试全绿却什么都没保住。
  test('反向自证：合法 target 走同一条路径放行', () => {
    const uri = 'mongodb://u:p@mongo:27017/fsms';
    expect(swapHost(uri, 'mongo')).toBe('rc=0|out=mongodb://u:p@mongo/fsms');
    expect(swapHost(uri, '127.0.0.1:27017')).toBe('rc=0|out=mongodb://u:p@127.0.0.1:27017/fsms');
    expect(swapHost(uri, 'db-1.internal')).toBe('rc=0|out=mongodb://u:p@db-1.internal/fsms');
    // 缺陷 4：IPv6 容器地址作为**目标**曾被撞旧字符集判据拒掉，而 URI 里写同一段是放行的
    // （同一件事两侧判据不一致）。现在两边共用 mongo_valid_hostport，两边都放行。
    expect(swapHost(uri, '[::1]:27017')).toBe('rc=0|out=mongodb://u:p@[::1]:27017/fsms');
    expect(swapHost(uri, '[::1]')).toBe('rc=0|out=mongodb://u:p@[::1]/fsms');
    // `+srv` 的拒绝条件是"目标带端口"，不是"+srv 一律不处理"：
    // 目标是裸服务名时产物 `mongodb+srv://u:p@mongo/fsms` 是解析器认的形态 ⇒ 放行
    expect(swapHost('mongodb+srv://u:p@cluster0.example.net/fsms', 'db.internal')).toBe(
      'rc=0|out=mongodb+srv://u:p@db.internal/fsms'
    );
  });

  test('凭据段绝不丢失（改写只动主机段）', () => {
    const out = swapHost('mongodb://admin:s3cr3t@mongo:27017/fsms', T);
    expect(out).toContain('admin:s3cr3t@');
    expect(out).not.toContain('mongo:27017');
  });

  /**
   * 承重判据：逐行拿**参考解析器**读一遍上面真值表里每一条 rc=0 的产物。
   * 清单从真值表推导而不是另抄一份（同一口径见 compose `:?` 清单闸）：新加一条
   * rc=0 的行，它自动进这道闸；删掉一条，`accepted.length` 那条前提自证会响。
   */
  test('每一条放行的产物：主机段确实被换成承诺的目标，库名与凭据没动', () => {
    const accepted = cases.filter(([, expected]) => expected.startsWith('rc=0'));
    // 前提自证：放行那一批不能是空集（否则上面整个循环只是在对空数组断言真）
    expect(accepted.length).toBeGreaterThanOrEqual(15);

    const violations = [];
    const inherited = [];
    for (const [uri] of accepted) {
      const got = swapHost(uri, T);
      if (!got.startsWith('rc=0|out=')) {
        violations.push(`  ${uri}：真值表说 rc=0，同一条实跑却是 ${got}（判据漂移）`);
        continue;
      }
      const output = got.slice('rc=0|out='.length);
      const verdict = parityViolations({ input: uri, output, target: T });
      if (verdict === null) inherited.push(uri);
      else violations.push(...verdict.map((v) => `  ${uri}：${v}`));
    }
    expect(violations).toEqual([]);
    // 唯一一类"故障继承自输入"的放行产物：必须逐名点名，不得成批沉默。
    // 这一条的输入与产物都在**查询参数名**上被拒（`drop` 不是合法 option），
    // 结构上两边同形 ⇒ 改写没有制造新故障，但也不假装修好了它。
    expect(inherited).toEqual([`mongodb://${T}/fsms?drop:true`]);
  });
});

describe('参考解析器这道闸本身有牙（合成违例必须被点名）', () => {
  const T = '127.0.0.1:27017';

  /**
   * 旧判据"产物与原串不同 ⇒ 认为改写成功"的四种真实失效形态，逐个喂给新闸。
   * 这一条是整道 parity 闸的反向自证：如果它对旧产物也返回"没问题"，
   * 那新闸就是假的——全绿却什么都没保住。
   */
  const legacy = [
    [
      '缺陷 1：主机段没动，目标地址被拼进查询串（旧写法实测 rc=0 的产物）',
      'mongodb://u:p@db.internal:27017?appname=bob@corp',
      'mongodb://u:p@db.internal:27017?appname=bob@127.0.0.1:27017',
      'db.internal:27017',
    ],
    [
      '缺陷 5a：+srv 形态带端口（mongodump 直接拒）',
      'mongodb+srv://u:p@cluster0.example.net/fsms',
      'mongodb+srv://u:p@127.0.0.1:27017/fsms',
      null,
    ],
    [
      // 这一条不是"闸漏了"而是"故障继承自输入"：输入 `mongodb://h:27017/db@x` 自己就解析不动，
      // 产物 `mongodb://127.0.0.1:27017/db@x` 抛的是**同一句**错。旧写法真正的错是"该拒的输入
      // 没拒"，那由下面的「解析器拒的输入我们也拒」那条钉，不归这道逐行比较管。
      '缺陷 5b：无凭据时把带裸 @ 的库名交回去（由 refuse 侧那条判据点名）',
      'mongodb://h:27017/db@x',
      'mongodb://127.0.0.1:27017/db@x',
      null,
      'inherited',
    ],
    [
      '缺陷 5c：凭据分界取最后一个 @，产物里留下裸 @',
      'mongodb://a@b@c:27017/db',
      'mongodb://a@b@127.0.0.1:27017/db',
      null,
    ],
    [
      '凭据被静默丢弃（旧 sed 形态的错位产物）',
      'mongodb://u:p@mongo:27017/fsms',
      'mongodb://127.0.0.1:27017/fsms',
      null,
    ],
    ['库名被动过', 'mongodb://u:p@mongo:27017/fsms', 'mongodb://u:p@127.0.0.1:27017/otherdb', null],
  ];
  /**
   * 形参**必须带默认值**，不能写成 `(name, input, output, expectHosts, kind)`：
   * jest-each@29.7.0 的 `applyArguments`（bind.js:78-80）是
   * `params.length < test.length ? (done) => test(...params, done) : () => test(...params)`
   * ——行数组比函数声明的形参短，最后一个实参就变成 `done`，测试被当成 done 风格，
   * 而没人会调它 ⇒ 30 秒后**超时**，不是断言失败。实测形状：6 行表里 5 行少写一个元素，
   * 于是 5 条超时 + 1 条真失败，看起来像整道 parity 闸坏了。
   * `Function.length` 停在第一个带默认值的形参之前，所以这里声明出来的形参数是 3，
   * 短一行的表再也注入不进 done；下面的 `表宽` 那条把这件事钉成判据（含合成违例）。
   */
  const runLegacy = (name, input, output, expectHosts = null, kind = null) => {
    const verdict = parityViolations({ input, output, target: T });
    if (kind === 'inherited') {
      // 成对判据：这一类必须**只**在"两边同一句错"时才被判为继承。
      // 若把继承规则写成"输入解析不动就放过"，上面那些真违例会一起被放过。
      expect({ name, verdict }).toEqual({ name, verdict: null });
      expect(parseUri(input).why).toBe(parseUri(output).why);
      expect(swapHost(input, T)).toBe('rc=1|out=');
      return;
    }
    expect({ name, verdict: verdict === null ? 'GATE MISSED IT' : verdict }).not.toEqual({
      name,
      verdict: 'GATE MISSED IT',
    });
    expect(verdict.length).toBeGreaterThanOrEqual(1);
    if (expectHosts) expect(verdict[0]).toContain(expectHosts);
  };
  test.each(legacy)('%s', runLegacy);

  test('表宽 ≥ 测试函数形参数（短一行就会被注入 done ⇒ 超时而不是断言失败）', () => {
    // 机制前提：带默认值的形参不计入 Function.length
    expect({ declared: runLegacy.length }).toEqual({ declared: 3 });
    expect(fitsTable(runLegacy, legacy)).toBe(true);
    // 判据自身要有牙：同一张表配上"5 个无默认值形参"的签名必须判 false
    // （那正是上面注释里被否定的写法，它会在这 6 行里挂掉 5 行）
    const fiveParams = (n, i, o, eh, k) => [n, i, o, eh, k];
    expect({ synthetic: fitsTable(fiveParams, legacy) }).toEqual({ synthetic: false });
  });

  // 反向自证：闸不是"什么都判红"——正确的改写必须返回空数组
  test('反向自证：一条正确的改写判为无违规', () => {
    expect(
      parityViolations({
        input: 'mongodb://u:p@mongo:27017/fsms?authSource=admin',
        output: `mongodb://u:p@${T}/fsms?authSource=admin`,
        target: T,
      })
    ).toEqual([]);
    // 主机等价性按解析器的读法判：目标不带端口时它补默认端口，所以 `db.internal`
    // 与产物里的 `db.internal:27017` 必须判为同一个主机（否则这条闸会假红）
    expect(
      parityViolations({
        input: 'mongodb://u:p@mongo:27017/fsms',
        output: 'mongodb://u:p@db.internal/fsms',
        target: 'db.internal',
      })
    ).toEqual([]);
    expect(normalizeTarget('[::1]')).toBe('[::1]:27017');
    expect(normalizeTarget('[::1]:27018')).toBe('[::1]:27018');
  });
});

describe('输入形态的拒绝判据（只管结构，不管驱动的 option 白名单）', () => {
  const T = '127.0.0.1:27017';

  /**
   * 第一类：解析器自己就抛错。这类必须两边都拒——把坏串交回调用方等于让 mongodump
   * 报一个和"主机段被改写"毫无关系的错，现场只会说"脚本坏了"。
   * 刻意**不**扩到 option 名：`?drop:true` 那行驱动也拒，但我们放行（真值表里把它当
   * 换行判据的反向自证），因为 mongodump 对查询串按自己的规则处理，且改写没有制造新故障。
   */
  const bothRefuse = [
    'mongodb://h:27017/db@x',
    'mongodb://@h:27017/db',
    'mongodb://:p@h:27017/db',
    'mongodb://h:1:2/db',
    'mongodb://u:p/x@h:27017/db',
    'mongodb://u:p@[a b]:27017/db',
    'mongodb://u:p@[::1]x:27017/db',
  ];
  test.each(bothRefuse)('%s ⇒ 解析器抛错，我们也拒', (uri) => {
    expect({ name: uri, parsed: parseUri(uri).ok }).toEqual({ name: uri, parsed: false });
    expect(swapHost(uri, T)).toBe('rc=1|out=');
  });

  /**
   * 第二类（更危险）：解析器**不报错**，但它读出的主机不是运维写下的那几个字节。
   * 这类没有任何现场信号：备份安静地跑在另一台主机上，横幅还写着承诺的地址。
   * 每行都同时钉三件事：解析器放行、它实际读到的主机列表、我们拒。
   */
  const silentRetarget = [
    // 分界取最后一个 @ 时"主机 = c:27017"，而两个解析器都读成 `b`（凭据被拆成 a@… 与 b）
    ['mongodb://a@b@c:27017/db', ['b:27017']],
    // 同一族的两个变体（探针实测）：解析器**不报错**，但它把**中间**那一段读成主机——
    // 运维写的是 `h:27017`，实际被拨号的是 `ss` / `p`，而凭据被读成 `u:p@ss`（口令里的裸 `@`
    // 要求写成 `%40`）。这类形态连"错误信号"都没有，所以三条一起拒。
    ['mongodb://u:p@ss@h:27017/db', ['ss:27017']],
    ['mongodb://u@p@h:27017/db', ['p:27017']],
    // 空种子项不是报错，而是"多拨一个空主机"
    ['mongodb://h:27017,/db', ['h:27017', ':27017']],
    ['mongodb://,h:27017/db', [':27017', 'h:27017']],
    ['mongodb://h:27017,,ii:27018/db', ['h:27017', ':27017', 'ii:27018']],
    // 空端口被静默补成默认端口
    ['mongodb://h:/db', ['h:27017']],
  ];
  test.each(silentRetarget)('%s ⇒ 解析器读成 %j，我们拒', (uri, readAs) => {
    const p = parseUri(uri);
    expect({ name: uri, ok: p.ok }).toEqual({ name: uri, ok: true });
    // 取证：它确实读成这个（读法若随上游改版变化，这里先红，再回来重写判据）
    expect({ name: uri, hosts: p.hosts }).toEqual({ name: uri, hosts: readAs });
    expect(swapHost(uri, T)).toBe('rc=1|out=');
  });

  /**
   * 一条**负结果**，钉在这里而不是只写进注释：`mongodb://h#1/db` 曾按"`#` 不是主机字符 ⇒
   * 解析器会把它整个当主机吞掉 ⇒ 我们更严"归进上面那组，实测不成立——参考解析器在 `#`
   * 处终止 authority，读成 hosts=["h:27017"]、db="db"，与我们的取段判据完全同一口径，
   * 于是它属于"放行且产物忠实"那一类（上面真值表里那两行由逐行 parity 闸覆盖）。
   * 单独一条取证测试的意义：上游改版换了 `#` 的读法时这里先红，
   * 而不是等到某次备份安静地连到别处、或把库名丢掉时才发现。
   */
  test('# 的读法取证：不是"我们更严"，而是两边同一口径', () => {
    expect(parseUri('mongodb://h#1/db')).toEqual({
      ok: true,
      hosts: ['h:27017'],
      db: 'db',
      creds: null,
    });
    // 库名里的裸 `#` 被截断（片段起点），`%23` 才表示字面量 `#`
    expect(parseUri('mongodb://h/my#db')).toMatchObject({ ok: true, db: 'my' });
    expect(parseUri('mongodb://h/my%23db')).toMatchObject({ ok: true, db: 'my#db' });
    // 放行的两条：改写产物按解析器读法忠实（主机=目标，库名与凭据没动）
    expect(
      parityViolations({ input: 'mongodb://h#1/db', output: `mongodb://${T}#1/db`, target: T })
    ).toEqual([]);
    expect(
      parityViolations({
        input: 'mongodb://u:p@h/my#db',
        output: `mongodb://u:p@${T}/my#db`,
        target: T,
      })
    ).toEqual([]);
  });

  // 反向自证：上面两组不是"看着怪就拒"——同一族里合法的形态必须两边都放行
  const bothAccept = [
    'mongodb://u:p@mongo/db@name',
    'mongodb://u:p@mongo:27017/db@name',
    'mongodb://h:27017?directConnection=true',
    'mongodb://a:27017,b:27017/db?replicaSet=rs0',
    'mongodb://u:p@[::1]:27017/fsms',
    'mongodb://u:p@[::1]/fsms',
    'mongodb://u:@h:27017/db',
    'mongodb://u@h:27017/db',
  ];
  test.each(bothAccept)('%s ⇒ 解析器放行，我们也改写', (uri) => {
    expect(parseUri(uri).ok).toBe(true);
    expect(swapHost(uri, T).startsWith('rc=0|out=')).toBe(true);
  });
});

describe('helper 层的判据细节（整条 URI 被拒时要知道是哪条点亮的）', () => {
  const rows = [
    ['mongo_valid_hostport', '[::1]', 'rc=0'],
    ['mongo_valid_hostport', '[::1]:27017', 'rc=0'],
    ['mongo_valid_hostport', '[fF00::1]', 'rc=0'],
    ['mongo_valid_hostport', 'mongo-1.internal:27017', 'rc=0'],
    ['mongo_valid_hostport', 'h', 'rc=0'],
    ['mongo_valid_hostport', '[::1]:', 'rc=1'],
    ['mongo_valid_hostport', '[::1]x', 'rc=1'],
    ['mongo_valid_hostport', '[::1]:1:2', 'rc=1'],
    ['mongo_valid_hostport', '[a b]', 'rc=1'],
    ['mongo_valid_hostport', '[::1', 'rc=1'],
    ['mongo_valid_hostport', 'h:1:2', 'rc=1'],
    ['mongo_valid_hostport', 'h:', 'rc=1'],
    ['mongo_valid_hostport', ':27017', 'rc=1'],
    ['mongo_valid_hostport', 'a[b]c', 'rc=1'],
    ['mongo_valid_hostport', 'a;b', 'rc=1'],
    ['mongo_valid_hostport', 'a|b', 'rc=1'],
    ['mongo_valid_hostport', 'a`id`', 'rc=1'],
    ['mongo_valid_hostport', 'a$b', 'rc=1'],
    ['mongo_valid_hostport', 'a\\b', 'rc=1'],
    ['mongo_valid_hostport', 'bad host', 'rc=1'],
    ['mongo_valid_hostport', '127.0.0.1:27017\\ncollection:auditLog', 'rc=1'],
    ['mongo_valid_hostport', 'h:27017,ii:27018', 'rc=1'],
    ['mongo_valid_hostport', '', 'rc=1'],
    // 端口区间经由 hostport 也判一次（两条分支共用 mongo_valid_port，这里钉住接线没断）
    ['mongo_valid_hostport', 'h:0', 'rc=1'],
    ['mongo_valid_hostport', 'h:65535', 'rc=0'],
    ['mongo_valid_hostport', '[::1]:0', 'rc=1'],
    // mongo_valid_port 的区间判据逐点钉：端点 / 越界的每一段 / 位数 / 前导零 / 非数字。
    // `08` 那条钉的是"不用 `$(( ))`"这个选择——shell 把 0 前缀当八进制，`08` 会算错，
    // 而解析器把它读成 8（实测 `07017` ⇒ 7017），所以这里必须是字符串判据。
    ['mongo_valid_port', '1', 'rc=0'],
    ['mongo_valid_port', '65535', 'rc=0'],
    ['mongo_valid_port', '07017', 'rc=0'],
    ['mongo_valid_port', '08', 'rc=0'],
    ['mongo_valid_port', '0', 'rc=1'],
    ['mongo_valid_port', '65536', 'rc=1'],
    ['mongo_valid_port', '65540', 'rc=1'],
    ['mongo_valid_port', '65600', 'rc=1'],
    ['mongo_valid_port', '66000', 'rc=1'],
    ['mongo_valid_port', '70000', 'rc=1'],
    ['mongo_valid_port', '99999', 'rc=1'],
    ['mongo_valid_port', '100000', 'rc=1'],
    ['mongo_valid_port', '123456', 'rc=1'],
    ['mongo_valid_port', '00000', 'rc=1'],
    ['mongo_valid_port', '', 'rc=1'],
    ['mongo_valid_port', 'abc', 'rc=1'],
    // 判据不是"看着长就拒"：同一区间里逐个十步进界必须一路放行到 65535
    ['mongo_valid_port', '65534', 'rc=0'],
    ['mongo_valid_port', '9999', 'rc=0'],
    ['mongo_valid_hostlist', 'h:27017,ii:27018', 'rc=0'],
    ['mongo_valid_hostlist', 'h,a', 'rc=0'],
    ['mongo_valid_hostlist', 'h:27017,', 'rc=1'],
    ['mongo_valid_hostlist', ',h:27017', 'rc=1'],
    ['mongo_valid_hostlist', 'h,,a', 'rc=1'],
    ['mongo_valid_hostlist', '', 'rc=1'],
    ['mongo_valid_userinfo', 'a:b', 'rc=0'],
    ['mongo_valid_userinfo', 'u', 'rc=0'],
    ['mongo_valid_userinfo', 'u:', 'rc=0'],
    ['mongo_valid_userinfo', 'a:b:c', 'rc=1'],
    ['mongo_valid_userinfo', 'u[p', 'rc=1'],
    ['mongo_valid_userinfo', 'u]p', 'rc=1'],
  ];
  test.each(rows)('%s(%s)', (fn, arg, expected) => {
    expect(callHelper(fn, arg)).toBe(expected);
  });

  // 真换行那一臂单独构造：裸控制字符塞进 `bash -c` 的命令串会在传输层被吃掉（假绿），
  // 上一批 badTargets 用的就是这个形态，这里把它接到 hostport 判据上。
  test('真换行与空格在 hostport 判据上点亮（同形无越界字节必须放行）', () => {
    const built = (expr) =>
      execFileSync(
        'bash',
        ['-c', `. ${sq(HELPER_POSIX)}; h=$(${expr}); mongo_valid_hostport "$h"; echo "rc=$?"`],
        { encoding: 'utf8' }
      ).trim();
    expect(built(`printf '127.0.0.1:27017\\ncollection:auditLog'`)).toBe('rc=1');
    expect(built(`printf '127.0.0.1:27017collection:auditLog'`)).toBe('rc=1');
    expect(built(`printf '127.0.0.1:27017'`)).toBe('rc=0');
  });

  /**
   * 这一臂钉的是一个**写 case 模式时的语言陷阱**，它让新加的判据静默失效过一次：
   * 给 `*` 加引号会让它变成字面量星号，于是 `'*,')`（"以逗号结尾"）永不命中，
   * `mongodb://h:27017,/db` 这种空种子项被放行。实测对比：
   *   `case "h:27017," in "*,") echo hit;; esac`   ⇒ 不命中
   *   `case "h:27017," in *,) echo hit;; esac`     ⇒ 命中
   * 逗号本身不是元字符，不需要引号；本文件其它带引号的模式都只引首字符
   * （`'@'*`、`*'['*`），那才是"字面量 + 通配"的正确写法。
   * 判据用真跑而不是读源码：源码里写 `'*,')` 还是 `*,)` 只有一行差别，而行为差别是
   * "副本集列表里的空项能不能通过"。
   */
  test('反向自证：hostlist 的逗号判据没被引号陷阱吃掉', () => {
    expect(callHelper('mongo_valid_hostlist', 'h:27017,')).toBe('rc=1');
    expect(callHelper('mongo_valid_hostlist', 'h:27017,ii:27018')).toBe('rc=0');
    // 同一条陷阱在合成模式上的直接演示（不依赖被测实现）
    const probe = execFileSync(
      'bash',
      ['-c', `s='h:27017,'; case "$s" in "*,") echo quoted;; *) echo missed;; esac`],
      { encoding: 'utf8' }
    ).trim();
    expect(probe).toBe('missed');
  });
});

describe('mongo_validate_uri 的值判据（真换行注入）', () => {
  const rows = [
    ['mongodb://u:p@h/db', 'rc=0|msg='],
    // 只有换行、注入部分本身全是可打印 ASCII：命令替换会剥掉尾部换行，
    // 所以判据必须带哨兵字符，否则"残串为空"是假象 ⇒ drop:true 成为配置第二行
    ['mongodb://u:p@h/db\ndrop:true', 'rc=1'],
    ['mongodb://u:p@h/db?authSource=admin\ndrop: true', 'rc=1'],
    ['mongodb://u:p@h/d b', 'rc=1'],
    ['http://h/db', 'rc=1'],
  ];
  test.each(rows)('%s', (uri, expected) => {
    const got = validateUri(uri);
    if (expected.startsWith('rc=0')) {
      expect(got).toBe(expected);
      return;
    }
    expect(got.startsWith('rc=1|msg=Error:')).toBe(true);
    // 消息点名标签与原因，但绝不回显载荷（配置文件里那些字节不能被抄进日志）
    expect(got).toContain('标签');
    expect(got).not.toContain('drop');
  });

  // CR（CRLF 密钥文件、Windows 编辑器残留）走现场构造那一臂
  test('CR 载荷拒绝，同形无 CR 串放行（成对判据，防 CR 被传输层吃掉造成假绿）', () => {
    expect(validateUriBuilt(`printf 'mongodb://u:p@h/db'`)).toBe('rc=0|msg=');
    expect(validateUriBuilt(`printf 'mongodb://u:p@h/db\\r'`)).toMatch(/^rc=1\|msg=Error: 标签/);
  });

  // 反向自证：哨兵判据不是"什么都拒"——去掉一个越界字节的同形串必须放行
  test('反向自证：无换行的同形串放行', () => {
    expect(validateUri('mongodb://u:p@h/db?authSource=admin&drop:true')).toBe('rc=0|msg=');
  });
});

describe('备份与恢复共用同一份判据，且两侧都有传输开关', () => {
  const backup = read(BACKUP);
  const restore = read(RESTORE);
  const helper = read(HELPER);

  test('两个脚本都 source 共享实现，且都不再自带那句 sed', () => {
    for (const [name, src] of [
      ['backup', backup],
      ['restore', restore],
    ]) {
      // 必须是"可执行的一行"而不是注释：注释掉 source 同样含 mongoUri.sh 字样，
      // 纯文本判据拦不住"删掉调用"（本仓反复踩过的假绿形状）。
      const line = src.match(/^[ \t]*\.[ \t]*".*mongoUri\.sh.*$/m);
      expect({ name, hasSourceLine: Boolean(line) }).toEqual({ name, hasSourceLine: true });

      // 真跑脚本自己那行表达式：bash -c 的第 4 个参数就是 $0 ⇒ 必须是脚本路径本身
      const rel = name === 'backup' ? 'scripts/backup-mongo.sh' : 'scripts/restore-mongo.sh';
      const probe = execFileSync(
        'bash',
        ['-c', `${line[0].trim()}\ntype -t mongo_swap_host`, rel],
        { encoding: 'utf8', cwd: ROOT }
      );
      expect({ name, loaded: probe.trim() }).toEqual({ name, loaded: 'function' });

      expect({ name, hasOwnSed: /\bsed\b[^\n]*mongodb/.test(src) }).toEqual({
        name,
        hasOwnSed: false,
      });
    }
    // 反向前提换了方向：这里原来断言"那句 sed 必须还存在于共享实现里"（用来证明
    // 上面几条不是空集）。sed 形态带着两个静默失效（字面 `\n` 被展开成真换行、
    // 口令里未转义的 `/` 让替换错位并丢掉凭据），实现已改成纯 shell 重建，
    // 于是判据变成"主机段改写函数体内不许出现 sed"。
    // 判据自身仍要非空集：把历史写法作为合成违例喂给同一个判据，它必须点亮。
    const swapImpl = helper.match(/^mongo_swap_host\(\)\s*\{[\s\S]*?^\}/m);
    expect(swapImpl).not.toBeNull();
    // 「注释不执行，不能当证据」在这里是双向的：函数体里的注释**提到** sed 是允许的
    // （本文件正是靠注释记录那句写法为什么被删），判据只看有没有真的调用。
    const codeOnly = (text) =>
      text
        .split('\n')
        .filter((l) => !/^[ \t]*#/.test(l))
        .join('\n');
    const hasSed = (text) => /\bsed\b/.test(codeOnly(text));
    expect({ sedInSwapImpl: hasSed(swapImpl[0]) }).toEqual({ sedInSwapImpl: false });
    const legacyForm =
      '  _swapped=$(printf %s "$_uri" |' +
      ' sed -E "s#^((mongodb(\\+srv)?://)([^/]*@)?)[^/]*#\\1${_target}#")';
    expect({ syntheticViolator: hasSed(legacyForm) }).toEqual({ syntheticViolator: true });
    // 注释过滤本身也要自证：注释掉的同一句必须不点亮，否则"实现里没有 sed"
    // 只是因为判据把整行注释都删了——那它同样删得掉真的调用。
    expect({ commentedOut: hasSed('  # _swapped=$(… | sed -E "s#a#b#")') }).toEqual({
      commentedOut: false,
    });
    // 函数体确实被取到了（不是 `null` 蒙混过关）：它必须含重建那一步
    expect(swapImpl[0]).toContain('${_scheme}://${_creds}@${_target}${_tail}');
  });

  test('两侧都有 local|docker 开关，且默认值一致（恢复侧曾完全没有）', () => {
    for (const [name, src, varName] of [
      ['backup', backup, 'MONGO_BACKUP_TRANSPORT'],
      ['restore', restore, 'MONGO_RESTORE_TRANSPORT'],
    ]) {
      expect({
        name,
        declares: new RegExp(`${varName}=\\$\\{${varName}:-docker\\}`).test(src),
      }).toEqual({ name, declares: true });
      for (const arm of ['local)', 'docker)', '*)']) {
        expect({ name, arm: src.includes(arm) }).toEqual({ name, arm: true });
      }
    }
  });

  test('反向前提：注释掉的 source 行不算数（纯文本判据防不住"删掉调用"）', () => {
    const re = /^[ \t]*\.[ \t]*".*mongoUri\.sh.*$/m;
    expect(re.test('. "$(dirname "$0")/mongoUri.sh"')).toBe(true);
    expect(re.test('# . "$(dirname \\"$0\\")/mongoUri.sh"')).toBe(false);
    expect(re.test('  # sourced elsewhere')).toBe(false);
  });

  test('恢复侧的口令保护与门禁没有因为改动而退化', () => {
    // 凭据只进 0600 配置文件或管道，不进 argv
    expect(restore).toMatch(/umask 077/);
    expect(restore).toMatch(/chmod 600 "\$CONFIG_FILE"/);
    expect(restore).toMatch(/--config="\$CONFIG_FILE"/);
    // 容器分支同样不得把 URI 拼进 argv：只走 stdin（`read -r` 吃掉首行配置）
    expect(restore).toMatch(/IFS= read -r/);
    expect(restore).toMatch(/printf 'uri: %s\\n' "\$CONTAINER_URI"/);
    // 三道门禁仍在**真正执行**之前（拿执行语句而不是文件里第一次出现的名词做基准，
    // 否则会被头部注释里的 "mongorestore 会把归档内容…" 抢先命中而误判）
    const execAt = restore.indexOf('mongorestore "${RESTORE_ARGS[@]}"');
    expect(execAt).toBeGreaterThan(-1);
    expect(restore.indexOf('RESTORE_CONFIRM')).toBeLessThan(execAt);
    expect(restore.indexOf('请键入目标库名')).toBeLessThan(execAt);
  });

  test('两个脚本都能被 bash 解析（语法错误只会在真正要恢复时才暴露）', () => {
    for (const p of [HELPER, BACKUP, RESTORE]) {
      expect(execFileSync('bash', ['-n', p], { encoding: 'utf8' })).toBe('');
    }
  });
});
