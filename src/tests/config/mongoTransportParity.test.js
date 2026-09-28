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

/** 真跑一次 URI 改写；bash 缺失时直接判红（不用 skip 制造假绿） */
function swapHost(uri, target) {
  const script = `. '${HELPER.replace(/\\/g, '/')}'; out=$(mongo_swap_host "${uri}" "${target}"); echo "rc=$?|out=$out"`;
  const stdout = execFileSync('bash', ['-c', script], { encoding: 'utf8' });
  return stdout.trim();
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
  ];
  test.each(cases)('%s', (uri, expected) => {
    expect(swapHost(uri, T)).toBe(expected);
  });

  test('凭据段绝不丢失（改写只动主机段）', () => {
    const out = swapHost('mongodb://admin:s3cr3t@mongo:27017/fsms', T);
    expect(out).toContain('admin:s3cr3t@');
    expect(out).not.toContain('mongo:27017');
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
    // 反向前提：那句 sed 必须确实还存在于共享实现里（否则上面几条是空集假绿）
    expect(helper).toMatch(/sed -E "s#\^\(\(mongodb/);
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
