'use strict';

/**
 * 入口脚本的「队列权限改不动就告警放行」分支：成与败必须走对边
 *
 * 缺陷形态（2026-10-30 审计）：块写成
 *   if ! { chmod…; chown…; } 2>/dev/null; then : ; else echo "…失败…"; return 0; fi
 * 也就是「成功走 else、失败走 :」——恰好反了。后果有两层，且都不响：
 *   ① 成功时打一条**假告警**（"权限适配失败"），并在 return 0 里**跳过**后面的
 *      find -exec chown/chmod 归一化 ⇒ 首启前留下的旧文件永远不带新权限矩阵；
 *   ② 失败时反而静默继续，真正该出现的那条告警永远不出现。
 * 这类"两个分支都错、且都不报错"的写法，纯文本断言钉不住，所以判据是**真跑**：
 * 从入口脚本里抽出这一整块，用桩 chmod/chown/chgrp 分别造出"全成功"与"某一环失败"，
 * 看它是不是 ①成功继续、②失败告警并提前返回。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { resolveShell } = require('../helpers/posixShell');

const ROOT = path.resolve(__dirname, '../../..');
const ENTRYPOINT = path.join(ROOT, 'docker', 'app-entrypoint.sh');
const BASH = (resolveShell() || { cmd: null }).cmd;
const group = BASH ? describe : describe.skip;

if (!BASH && process.env.CI) {
  // 同 imageDigestGate.test.js:80-89 的口径：CI ubuntu 必有 POSIX shell，探不到即为探测失效 ⇒ 红。
  describe('app-entrypoint 的平台前提（CI 上缺 POSIX shell）', () => {
    test('CI 上 resolveShell 必须解析到可用的 POSIX shell，否则本文件全部覆盖都是假的', () => {
      expect(BASH).toBeTruthy();
    });
  });
}
if (!BASH) {
  console.warn('[跳过] 未找到可用的 POSIX shell：入口脚本权限适配分支无法真跑（CI 会跑）');
}

/** 抽出 "if ! { … } 2>/dev/null; then … fi" 这一整块（从脚本原文取，不另抄一份） */
function extractBlock() {
  const src = fs.readFileSync(ENTRYPOINT, 'utf8');
  const start = src.indexOf('if ! {');
  expect(start).toBeGreaterThan(-1);
  const end = src.indexOf('\n  fi\n', start);
  expect(end).toBeGreaterThan(start);
  return src.slice(start, end + '\n  fi\n'.length);
}

/**
 * 跑一遍抽出来的块。
 * failOn：返回非零的桩命令（'chmod' / 'chown' / 'chgrp' / null=全成功）
 */
function runBlock(blockSource, opts = {}) {
  const failAt = opts.failAt || 0; // 0 = 一次都不失败；N = 第 N 次调用失败
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'entrypoint-perm-'));
  try {
    const posixDir = dir.split(path.sep).join('/');
    const script = [
      'set -eu',
      'QUEUE_DIR=' + posixDir,
      'n=0',
      'fail_at=' + failAt,
      'chmod() { n=$((n+1)); [ "$n" -ne "$fail_at" ]; }',
      'chown() { n=$((n+1)); [ "$n" -ne "$fail_at" ]; }',
      'chgrp() { n=$((n+1)); [ "$n" -ne "$fail_at" ]; }',
      'prepare_upgrade_queue_perms() {',
      blockSource,
      '  echo CONTINUED',
      '}',
      'prepare_upgrade_queue_perms',
      'echo "rc=$?"',
    ].join('\n');
    // timeout 是必需的：子 shell 卡住时不要连整条 CI 一起挂死（A6/S3）。
    // 超时时 spawnSync 返回 status=null + error，上面那句 `rc=$?` 的断言会自己红。
    const r = spawnSync(BASH, ['-c', script], { encoding: 'utf8', timeout: 30000 });
    return { status: r.status, out: String(r.stdout || '') + String(r.stderr || '') };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * 把权限适配块改成历史上的「逐行并列」形态（`&&` 换成分号）。
 * 反例对照：同一夹具下它必须被抓住，否则本闸对「逐条 &&」这条不变量没有判别力。
 */
function asSemicolonForm(blockSource) {
  return blockSource.replace(/ &&\n/g, '\n').replace(/ &&$/gm, '');
}
/** 反例对照：把两个分支对调回来（历史上真实存在过的形态），用同一夹具跑 */
const INVERTED = [
  'if ! {',
  '  chmod 0750 "$QUEUE_DIR"',
  '  chown nodejs:nodejs "$QUEUE_DIR/requests"',
  '} 2>/dev/null; then',
  '  :',
  'else',
  '  echo "app-entrypoint: 警告：升级队列权限适配失败" >&2',
  '  return 0',
  'fi',
].join('\n');

group('docker/app-entrypoint.sh：权限适配失败才告警放行，成功要继续做归一化', () => {
  test('前提自证：抽出来的块确实同时含 chmod、chown 两段（不是空块）', () => {
    const block = extractBlock();
    expect(block).toContain('chmod 0750 "$QUEUE_DIR"');
    expect(block).toContain('chown nodejs:nodejs "$QUEUE_DIR/requests"');
    expect(block).toContain('if ! {');
  });

  test('全成功 ⇒ 不许打"失败"告警，且必须继续往下走（归一化没被跳过），函数返回 0', () => {
    const r = runBlock(extractBlock(), { failAt: 0 });
    expect(r.out).toContain('CONTINUED');
    expect(r.out).not.toContain('权限适配失败');
    expect(r.out).toContain('rc=0');
  });

  /**
   * 逐条 && 的判别力（2026-10-30 第二轮审计的缺陷 1+2）。
   *
   * 旧夹具只有「整类命令全失败」一档：`chmod()` 一律 return 1 ⇒ 链上**第一条**就断，
   * 于是把 `&&` 换成 `;`（历史形态）照样被抓住，而「只断在中间第 N 条」这种真实形态
   * （只读 bind 上某一个子目录不可写）根本跑不到。这里逐条注入：第 N 次调用失败，N=1..8。
   * `{ a; b; c; }` 的退出码只取最后一条，且 if 的条件列表不受 set -e 约束 ⇒ 中间一条失败
   * 会被静默吞掉、剩下的命令继续跑 —— 这正是本块注释里声明要挡的形态，必须能被单独钉住。
   */
  test('逐条 &&：链上任意第 N 条失败都必须告警并提前返回（不许中间一条被静默吞掉）', () => {
    const block = extractBlock();
    // 前提自证：块里确实有 8 条命令、且每条之间都是 && 串联（否则下面的 N=1..8 是空转）
    const chained = block.match(/ &&\n/g) || [];
    expect(chained.length).toBe(7);
    for (let n = 1; n <= 8; n += 1) {
      const r = runBlock(block, { failAt: n });
      expect({
        n,
        warned: r.out.includes('权限适配失败'),
        continued: r.out.includes('CONTINUED'),
      }).toEqual({
        n,
        warned: true,
        continued: false,
      });
      // 「失败即放行」不是「失败即退出」：容器必须起得来（升级不可用而已）
      expect({ n, rc: r.out.includes('rc=0') }).toEqual({ n, rc: true });
    }
  });

  test('反向对照：`&&` 换成分号的历史形态，第 2 条失败被静默吞掉 ⇒ 本闸抓得住它', () => {
    const semicolon = asSemicolonForm(extractBlock());
    // 前提自证：替换真的发生了（否则这条对照测的是同一份源码）
    expect(semicolon).not.toBe(extractBlock());
    expect(semicolon).not.toMatch(/ &&\n/);
    const r = runBlock(semicolon, { failAt: 2 });
    // 分号形态下中间失败被吞 ⇒ 不打告警、照常继续：正是上面那条用例要禁止的形态
    expect(r.out).toContain('CONTINUED');
    expect(r.out).not.toContain('权限适配失败');
  });

  test('反向对照：分支对调的旧形态在同一夹具下"成功也告警 + 不继续"（本闸抓得住它）', () => {
    const r = runBlock(INVERTED, { failAt: 0 });
    expect(r.out).toContain('权限适配失败');
    expect(r.out).not.toContain('CONTINUED');
  });
});
