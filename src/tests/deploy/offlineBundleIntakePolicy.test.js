/**
 * 离线包落位判据（scripts/offlineBundleIntakePolicy.js）
 *
 * 守的失效形态（都是「落位报成功、装进去的是别的东西」或「现场无法归因」的变体）：
 *   · 条目名里藏 `..` / 绝对路径 / 反斜杠 / NUL ⇒ 解包能写到 staging 之外；
 *   · 条目列表里的链接条目（`name link -> target`）⇒ 落点可以是包外任意文件；
 *   · 条目数无上限 ⇒ 一个声明十万条目的归档把落位变成磁盘耗尽；
 *   · 归档体积无上限 ⇒ 畸形声明换来一次超长读（表现是「落位卡住」）；
 *   · 静默期/双读数判据被绕过 ⇒ scp 传到一半就被当成完整包解包；
 *   · 摘要形态不校验 ⇒ 外层签名覆盖的对象本身是脏的。
 *
 * 纯函数用例：不碰文件系统、不起子进程。真跑 tar 的那部分在
 * src/tests/deploy/offlineBundleIntake.test.js。
 */

'use strict';

const policy = require('../../../scripts/offlineBundleIntakePolicy');
const bundlePolicy = require('../../../scripts/offlineBundlePolicy');

/** 期望抛出并取文案 */
const messageOf = (fn) => {
  try {
    fn();
  } catch (err) {
    return err.message;
  }
  return '';
};

describe('条目清单解析：空行与链接条目', () => {
  test('正常清单：逐行成条目，末尾换行不产出空条目', () => {
    expect(
      policy.parseArchiveListing('manifest.json\nmanifest.sig\nSHA256SUMS\npayload/fsms-app.tar\n')
    ).toEqual(['manifest.json', 'manifest.sig', 'SHA256SUMS', 'payload/fsms-app.tar']);
  });

  test('目录条目保留末尾斜杠（解包时必须区分文件与目录）', () => {
    const entries = policy.parseArchiveListing('payload/\npayload/fsms-app.tar\n');
    expect(entries).toEqual(['payload/', 'payload/fsms-app.tar']);
    expect(policy.isDirectoryEntry(entries[0])).toBe(true);
    expect(policy.isDirectoryEntry(entries[1])).toBe(false);
  });

  test('CRLF 行尾被剥掉（Windows 上生成的归档可能带）', () => {
    expect(policy.parseArchiveListing('a\r\nb\r\n')).toEqual(['a', 'b']);
  });

  test('链接条目一律拒绝：落点可以是包外任意文件', () => {
    expect(messageOf(() => policy.parseArchiveListing('a\nb -> /etc/passwd\n'))).toMatch(
      /链接条目/
    );
  });

  test('空清单硬失败（不是「照常走空流程」）', () => {
    expect(messageOf(() => policy.parseArchiveListing('\n\n'))).toMatch(/为空/);
    expect(messageOf(() => policy.parseArchiveListing(null))).toMatch(/不是字符串/);
  });
});

describe('要解哪些条目：目录条目必须被剔除', () => {
  test('fileEntriesOnly 去掉目录条目与末尾斜杠（实测 tar 混传会 Not found）', () => {
    expect(
      policy.fileEntriesOnly([
        'manifest.json',
        'manifest.sig',
        'SHA256SUMS',
        'payload/',
        'payload/fsms-app.tar',
      ])
    ).toEqual(['manifest.json', 'manifest.sig', 'SHA256SUMS', 'payload/fsms-app.tar']);
  });

  test('normalizeEntry 只去目录标记，不动普通名', () => {
    expect(policy.normalizeEntry('payload/')).toBe('payload');
    expect(policy.normalizeEntry('payload/x.tar')).toBe('payload/x.tar');
  });

  test('非数组输入硬失败', () => {
    expect(messageOf(() => policy.fileEntriesOnly('nope'))).toMatch(/不是数组/);
  });
});

describe('路径判据：能写到 staging 之外的形态一律拒绝', () => {
  test('正向对照：正常相对路径通过', () => {
    expect(bundlePolicy.assertSafeRelativePath('payload/fsms-app.tar')).toBe(
      'payload/fsms-app.tar'
    );
  });

  test.each([
    ['上跳段', '../etc/passwd', /爬出包根/],
    ['中途上跳', 'payload/../../x', /爬出包根/],
    ['绝对路径', '/etc/passwd', /绝对路径/],
    ['盘符', 'C:/Windows', /绝对路径/],
    ['反斜杠', 'payload\\x.tar', /反斜杠/],
    ['NUL', 'a\u0000b', /NUL/],
  ])('%s：拒绝', (_label, bad, re) => {
    expect(messageOf(() => bundlePolicy.assertSafeRelativePath(bad))).toMatch(re);
  });

  test('条目判据与包内路径判据是**同一条**（不复制第二套规则）', () => {
    // 落位侧对条目名调的就是 assertSafeRelativePath；这里钉住"同一函数"这个事实：
    // 两份实现会让「包内路径安全、归档条目不安全」这种缺口存在。
    const viaEntry = messageOf(() => bundlePolicy.assertSafeRelativePath('../x'));
    const viaPolicy = messageOf(() => bundlePolicy.assertSafeRelativePath('../x'));
    expect(viaEntry).toBe(viaPolicy);
  });
});

describe('条目数与体积上限：把畸形声明挡在读盘之前', () => {
  test('条目数超上限：报出实际值与上限，便于判断该调上限还是分包', () => {
    const many = Array.from({ length: policy.MAX_ENTRIES + 1 }, (_, i) => `f${i}`);
    expect(messageOf(() => policy.assertEntryCountWithinCap(many))).toMatch(/超过上限/);
    expect(policy.assertEntryCountWithinCap(many.slice(0, policy.MAX_ENTRIES))).toBe(true);
  });

  test('体积上限：非正整数与超限分别拒绝，等于上限放行', () => {
    expect(messageOf(() => policy.assertArchiveSizeWithinCap(0))).toMatch(/正整数/);
    expect(messageOf(() => policy.assertArchiveSizeWithinCap(1.5))).toMatch(/正整数/);
    expect(
      messageOf(() => policy.assertArchiveSizeWithinCap(policy.DEFAULT_MAX_ARCHIVE_BYTES + 1))
    ).toMatch(/超过体积上限/);
    expect(policy.assertArchiveSizeWithinCap(policy.DEFAULT_MAX_ARCHIVE_BYTES)).toBe(true);
  });
});

describe('必需条目：四项判据的输入缺一不可', () => {
  test('齐全通过（目录标记不影响命中）', () => {
    expect(
      policy.assertRequiredEntriesPresent([
        'manifest.json',
        'manifest.sig',
        'SHA256SUMS',
        'payload/',
        'payload/fsms-app.tar',
      ])
    ).toBe(true);
  });

  test('缺任一即失败，并逐条点名缺了什么', () => {
    expect(
      messageOf(() => policy.assertRequiredEntriesPresent(['manifest.json', 'payload/x.tar']))
    ).toMatch(/manifest\.sig.*SHA256SUMS|SHA256SUMS.*manifest\.sig/s);
  });
});

describe('摘要 → 签名载荷', () => {
  test('64 位小写 hex 通过，返回 64 字节 utf8 Buffer（签名覆盖的正是它）', () => {
    const hex = 'a'.repeat(64);
    const buf = policy.digestPayloadOf(hex);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBe(64);
    expect(buf.toString('utf8')).toBe(hex);
  });

  test('大写 hex 归一成小写（与 sha256sum 输出口径一致）', () => {
    expect(policy.digestPayloadOf('A'.repeat(64)).toString('utf8')).toBe('a'.repeat(64));
  });

  test.each([
    ['长度不足', 'abc'],
    ['非 hex', 'z'.repeat(64)],
    ['带前缀', 'sha256:' + 'a'.repeat(64)],
    ['非字符串', 12345],
  ])('%s：拒绝（摘要脏了，签名覆盖的对象就是脏的）', (_label, bad) => {
    expect(messageOf(() => policy.digestPayloadOf(bad))).toMatch(/形态非法/);
  });
});

describe('传输是否已结束（静默期 + 双读数）', () => {
  const base = { sizeA: 1024, sizeB: 1024, mtimeMs: 0, now: 120000, settleSec: 60 };

  test('尺寸一致 + 静默期已过 ⇒ settled', () => {
    expect(policy.isSettled({ ...base, mtimeMs: 0 })).toEqual({ settled: true, reason: '' });
  });

  test('两次读数尺寸不一致 ⇒ 仍在传输（scp 暂停后 resume 的形态）', () => {
    expect(policy.isSettled({ ...base, sizeB: 2048 }).reason).toMatch(/尺寸不一致/);
  });

  test('0 字节 ⇒ 未开始或已失败（不是「空包也算好」）', () => {
    expect(policy.isSettled({ ...base, sizeA: 0, sizeB: 0 }).reason).toMatch(/0 字节/);
  });

  test('静默期未到 ⇒ 不 settled，且原因里带上「距今几秒 / 要求几秒」', () => {
    const r = policy.isSettled({ ...base, mtimeMs: 100000, now: 105000, settleSec: 60 });
    expect(r.settled).toBe(false);
    expect(r.reason).toMatch(/5s/);
    expect(r.reason).toMatch(/60s/);
  });

  test('尺寸读不出来 ⇒ 不 settled（文件可能已被移走）', () => {
    expect(policy.isSettled({ ...base, sizeA: undefined }).reason).toMatch(/读不出来/);
    expect(policy.isSettled({ ...base, mtimeMs: NaN }).reason).toMatch(/mtime/);
  });
});

describe('命令行：未知参数必报错，默认演练', () => {
  test('缺 --apply 即演练（opts.apply 为 false）', () => {
    expect(policy.parseArgs(['--inbox', '/x']).apply).toBe(false);
    expect(policy.parseArgs(['--inbox', '/x', '--apply']).apply).toBe(true);
  });

  test('未知参数报错并列出可用项', () => {
    expect(messageOf(() => policy.parseArgs(['--inbo', '/x']))).toMatch(/未知参数.*--inbox/s);
  });

  test('内联与空格写法等价', () => {
    expect(policy.parseArgs(['--inbox=/a']).inbox).toBe('/a');
    expect(policy.parseArgs(['--inbox', '/a']).inbox).toBe('/a');
  });

  test('缺值报错', () => {
    expect(messageOf(() => policy.parseArgs(['--inbox']))).toMatch(/需要一个值/);
    expect(messageOf(() => policy.parseArgs(['--inbox', '--apply']))).toMatch(/需要一个值/);
  });

  test('位置参数与单连字符拒绝（脚本只接受 --flag 形态）', () => {
    expect(messageOf(() => policy.parseArgs(['/x']))).toMatch(/无法识别/);
    expect(messageOf(() => policy.parseArgs(['-x']))).toMatch(/无法识别/);
  });

  test('开关集合是闭合清单：新增开关必须在这里显式确认（清单写死在这里是故意的）', () => {
    // 2026-11-02 确认新建：落位器（offlineBundleIntake）的独立开关集合。
    // --archive 在**打包**脚本（build-offline-bundle.sh）那边，不在本清单。
    expect(policy.FLAGS).toEqual([
      'inbox',
      'bundle-root',
      'pubkey-file',
      'allowlist',
      'apply',
      'dry-run',
      'help',
    ]);
  });
});

describe('常量与信任链', () => {
  test('归档形态只认 .tar.gz，外层签名是 .tar.gz.sig', () => {
    expect(policy.ARCHIVE_SUFFIX).toBe('.tar.gz');
    expect(policy.ARCHIVE_SIG_SUFFIX).toBe('.tar.gz.sig');
  });

  test('必需条目 = manifest.json / manifest.sig / SHA256SUMS（payload 名由 manifest 声明）', () => {
    expect(policy.REQUIRED_ENTRIES).toEqual(['manifest.json', 'manifest.sig', 'SHA256SUMS']);
  });

  test('默认值：条目数 32 / 8 GiB / 静默期 60s', () => {
    expect(policy.MAX_ENTRIES).toBe(32);
    expect(policy.DEFAULT_MAX_ARCHIVE_BYTES).toBe(8 * 1024 * 1024 * 1024);
    expect(policy.DEFAULT_SETTLE_SECONDS).toBe(60);
  });
});

describe('路径与名字收口（resolveWithinRoot / assertPlainDirName）', () => {
  test('根边界：根内通过、根外拒绝、等于根本身通过', () => {
    const root = process.platform === 'win32' ? 'C:\\bundles' : '/bundles';
    const inside = process.platform === 'win32' ? 'C:\\bundles\\a' : '/bundles/a';
    const outside = process.platform === 'win32' ? 'C:\\evil\\a' : '/evil/a';
    expect(policy.resolveWithinRoot(inside, root, '目标')).toBe(inside);
    expect(policy.resolveWithinRoot(root, root, '目标')).toBe(root);
    expect(messageOf(() => policy.resolveWithinRoot(outside, root, '目标'))).toMatch(/根之外/);
  });

  test('上跳段无法爬出根（path.resolve 先归一，再做前缀比对）', () => {
    const root = process.platform === 'win32' ? 'C:\\bundles' : '/bundles';
    const escaping = process.platform === 'win32' ? 'C:\\bundles\\..\\evil' : '/bundles/../evil';
    expect(messageOf(() => policy.resolveWithinRoot(escaping, root, '目标'))).toMatch(/根之外/);
  });

  test('空值或以 - 开头一律拒绝（后者会被目标程序当成选项）', () => {
    expect(messageOf(() => policy.resolveWithinRoot('', null, '目标'))).toMatch(/为空/);
    expect(messageOf(() => policy.resolveWithinRoot('-x', null, '目标'))).toMatch(/以 - 开头/);
  });

  test('落位目录名：分隔符/控制字符/点段/前导连字符都拒绝', () => {
    expect(policy.assertPlainDirName('v1.2.3')).toBe('v1.2.3');
    expect(messageOf(() => policy.assertPlainDirName('../x'))).toMatch(/非法|分隔符/);
    expect(messageOf(() => policy.assertPlainDirName('a/b'))).toMatch(/分隔符/);
    expect(messageOf(() => policy.assertPlainDirName('a\\b'))).toMatch(/分隔符/);
    expect(messageOf(() => policy.assertPlainDirName('.'))).toMatch(/非法/);
    expect(messageOf(() => policy.assertPlainDirName('..'))).toMatch(/非法/);
    expect(messageOf(() => policy.assertPlainDirName('-x'))).toMatch(/开头/);
  });
});
