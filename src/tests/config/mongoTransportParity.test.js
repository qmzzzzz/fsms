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

describe('mongo_swap_host 行为真值表', () => {
  const T = '127.0.0.1:27017';
  const cases = [
    ['mongodb://u:p%40ss@mongo:27017/fsms', `rc=0|out=mongodb://u:p%40ss@${T}/fsms`],
    [
      'mongodb://u:p@mongo:27017/fsms?replicaSet=rs0&authSource=admin',
      `rc=0|out=mongodb://u:p@${T}/fsms?replicaSet=rs0&authSource=admin`,
    ],
    [`mongodb+srv://u:p@cluster0.example.net/fsms`, `rc=0|out=mongodb+srv://u:p@${T}/fsms`],
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
    // 库名里的 `@` 合法（authority 终止于第一个 `/`），不得因为"尾部含 @"误杀
    ['mongodb://h/db@x', `rc=0|out=mongodb://${T}/db@x`],
    ['mongodb://u:p@mongo/db@name', `rc=0|out=mongodb://u:p@${T}/db@name`],
    // 值判据必须覆盖**两条**出口：改写那支已接，合法空操作那支也必须接。
    // 空操作那支少了这一步，"主机本来就等于目标地址"的 URI 就绕过全部检查被原样
    // 交回调用方，而调用方紧接着把它写进 mongodump 的 0600 配置（`\ndrop:true` 成为第二行）。
    [`mongodb://${T}/fsms\ndrop:true`, 'rc=1|out='],
    ['mongodb://u:p@mongo:27017/fsms\ndrop:true', 'rc=1|out='],
    // 成对的反向自证：同一载荷换成合法的查询串写法（无换行）必须放行，
    // 否则上面两条可能只是"任何带 drop 字样的串都拒"这种假严格
    [`mongodb://${T}/fsms?drop:true`, `rc=0|out=mongodb://${T}/fsms?drop:true`],
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

  // 反向自证：上面九条不是"任意 target 都拒"——同一夹具换成合法 target 必须放行，
  // 否则判据已经退化成无条件失败，测试全绿却什么都没保住。
  test('反向自证：合法 target 走同一条路径放行', () => {
    const uri = 'mongodb://u:p@mongo:27017/fsms';
    expect(swapHost(uri, 'mongo')).toBe('rc=0|out=mongodb://u:p@mongo/fsms');
    expect(swapHost(uri, '127.0.0.1:27017')).toBe('rc=0|out=mongodb://u:p@127.0.0.1:27017/fsms');
    expect(swapHost(uri, 'db-1.internal')).toBe('rc=0|out=mongodb://u:p@db-1.internal/fsms');
  });

  test('凭据段绝不丢失（改写只动主机段）', () => {
    const out = swapHost('mongodb://admin:s3cr3t@mongo:27017/fsms', T);
    expect(out).toContain('admin:s3cr3t@');
    expect(out).not.toContain('mongo:27017');
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
