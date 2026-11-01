/**
 * 离线包判据（scripts/offlineBundlePolicy.js）
 *
 * 这批用例守的不是「函数能跑」，而是五种「导入报告成功、实际装错包」的形态：
 *   · 只信 manifest.json —— 换掉 payload 的包能装成任意版本，而审计里记的是 manifest
 *     那句「自称」；离线侧没有 registry 可对质，只能靠「自称 ↔ 实际字节」逐条比对；
 *   · 摘要/大小不比 —— U 盘拷贝截断、传输损坏被当成完整包装上；
 *   · payload 路径不设约束 —— manifest 写上跳段、盘符、UNC 或反斜杠就能把文件写到包外；
 *   · 离线包放行 tag —— 「离线」成了 digest 钉扎的逃生通道（本套件单列一组钉住它）；
 *   · 空白名单被当成「全部放行」—— 把包拷进那个目录就等于能装任意代码。
 *
 * 全部只碰纯函数：不联网、不碰 docker、不写盘。
 */

const policy = require('../../../scripts/offlineBundlePolicy');
const hotUpgradePolicy = require('../../../scripts/hotUpgradePolicy');

/** 64 位小写十六进制；A/B 两份分别用于「相符」与「不符」两侧 */
const SHA256_A = 'a1'.repeat(32);
const SHA256_B = 'b2'.repeat(32);
const DIGEST_A = 'sha256:' + SHA256_A;
const REF_A = 'ghcr.io/qmzzzzz/fsms@' + DIGEST_A;
const TAR = 'payload/fsms-app.tar';

/** 一条合规的 manifest.images[i]；各用例只覆盖自己关心的那一个字段 */
const imageEntry = (over = {}) => ({
  role: 'app',
  ref: REF_A,
  file: TAR,
  bytes: 1024,
  sha256: SHA256_A,
  ...over,
});

/** 一份合规的 manifest.json */
const bundleManifest = (over = {}) => ({
  format: policy.BUNDLE_FORMAT_VERSION,
  version: '1.2.3',
  buildId: 'ci-20261101',
  createdAt: '2026-11-01T00:00:00.000Z',
  images: [imageEntry()],
  ...over,
});

/**
 * 断言抛出并取回文案。
 *
 * 错误文案是运维唯一能照抄修复的入口，所以这里不只断言「抛了」，还要能核对它说了什么。
 * 在没有抛时抛出的这条错误会直接成为失败信息：它指出的是「这条判据没有设防」。
 */
const messageOf = (fn) => {
  try {
    fn();
  } catch (err) {
    return String(err.message || err);
  }
  throw new Error('期望抛出错误，但调用没有抛——这条判据实际没有设防');
};

/** 与 messageOf 同用途，但允许「通过」的形态（用于钉住两个模块行为逐字一致） */
const outcomeOf = (fn) => {
  try {
    return { ok: true, value: fn() };
  } catch (err) {
    return { ok: false, message: String(err.message || err) };
  }
};

describe('包内路径：能写到包外的形态一律拒绝', () => {
  test('接受正常相对路径（正向对照：判据不得反向误伤唯一合法的形态）', () => {
    expect(policy.assertSafeRelativePath('payload/fsms-app.tar')).toBe('payload/fsms-app.tar');
    expect(policy.assertSafeRelativePath('  payload/fsms-app.tar  ')).toBe('payload/fsms-app.tar');
    expect(policy.assertSafeRelativePath('payload/2026/11/app.tar')).toBe(
      'payload/2026/11/app.tar'
    );
  });

  test.each([
    ['/etc/passwd'],
    ['/var/lib/fsms/upgrade/bundles/v1.2.3/payload/app.tar'],
    ['C:/payload/app.tar'],
    ['C:payload/app.tar'],
  ])('绝对路径或盘符 %s —— 拒绝（它直接指向包外任意位置）', (value) => {
    expect(() => policy.assertSafeRelativePath(value)).toThrow(/绝对路径/);
  });

  test('UNC 网络路径 —— 拒绝：在 Windows 上它指向网络位置，与「包内文件」无关', () => {
    expect(() => policy.assertSafeRelativePath('\\\\server\\share\\app.tar')).toThrow(/反斜杠/);
  });

  test('反斜杠路径 —— 拒绝：Windows 当分隔符、POSIX 当普通字符，两边必有一边被骗', () => {
    const msg = messageOf(() => policy.assertSafeRelativePath('payload\\..\\..\\app.tar'));
    expect(msg).toMatch(/反斜杠/);
    // 文案要说清为什么，否则下一个维护者会把它当成「风格洁癖」删掉
    expect(msg).toMatch(/Windows/);
  });

  test.each([['../app.tar'], ['payload/../app.tar'], ['payload/app.tar/..']])(
    '上跳段 %s —— 拒绝（用相对段爬出包根）',
    (value) => {
      expect(() => policy.assertSafeRelativePath(value)).toThrow(/爬出包根/);
    }
  );

  test.each([['payload//app.tar'], ['./payload/app.tar'], ['payload/']])(
    '空段或点段 %s —— 拒绝（同一路径有多种写法时，被校验的名字与真正打开的名字会不一致）',
    (value) => {
      expect(() => policy.assertSafeRelativePath(value)).toThrow(/空段/);
    }
  );

  test('NUL 字节 —— 拒绝：路径会被截断，校验名的对象与打开名的对象不是一回事', () => {
    const msg = messageOf(() => policy.assertSafeRelativePath('payload/app.tar\0.png'));
    expect(msg).toMatch(/NUL/);
  });

  test.each([[undefined], [null], [42], [''], ['   ']])('非字符串或空路径 %p —— 拒绝', (value) => {
    expect(() => policy.assertSafeRelativePath(value)).toThrow(/包内路径为空/);
  });
});

describe('manifest 结构：format 版本不符必须硬失败', () => {
  test('正向对照：合规范例被接受，并归一化出后续判据要用的字段', () => {
    const parsed = policy.parseBundleManifest(bundleManifest());
    expect(parsed.format).toBe(policy.BUNDLE_FORMAT_VERSION);
    expect(parsed.version).toBe('1.2.3');
    expect(parsed.images).toHaveLength(1);
    expect(parsed.images[0]).toEqual({
      role: 'app',
      ref: REF_A,
      repository: 'ghcr.io/qmzzzzz/fsms',
      digest: DIGEST_A,
      file: TAR,
      bytes: 1024,
      sha256: SHA256_A,
    });
  });

  test.each([[2], [0], ['1'], [undefined], [null]])(
    'format = %p —— 硬失败（老导入器读新包时「尽力而为」等于丢掉新版本才有的判据）',
    (format) => {
      const raw = bundleManifest();
      if (format === undefined) delete raw.format;
      else raw.format = format;
      expect(() => policy.parseBundleManifest(raw)).toThrow(/不支持的包格式版本/);
    }
  );

  test.each([[''], ['   '], [undefined], [123], [null]])(
    'version = %p —— 拒绝（留痕里必须能记下这次导入的是哪一版，否则回滚无从对账）',
    (version) => {
      const raw = bundleManifest();
      if (version === undefined) delete raw.version;
      else raw.version = version;
      expect(() => policy.parseBundleManifest(raw)).toThrow(/manifest\.version/);
    }
  );

  test.each([[null], [undefined], [[]], ['manifest.json'], [42]])(
    'manifest 根不是对象 %p —— 拒绝',
    (raw) => {
      expect(() => policy.parseBundleManifest(raw)).toThrow(/不是对象/);
    }
  );

  test('buildId / createdAt 缺省为空串（留痕字段可缺，版本与镜像不可缺）', () => {
    const parsed = policy.parseBundleManifest({
      format: policy.BUNDLE_FORMAT_VERSION,
      version: ' 1.2.3 ',
      images: [imageEntry()],
    });
    expect(parsed.version).toBe('1.2.3');
    expect(parsed.buildId).toBe('');
    expect(parsed.createdAt).toBe('');
  });
});

describe('images：没有镜像的离线包不是升级包', () => {
  test.each([[[]], [undefined], [{}], ['payload/app.tar'], [null]])(
    'images = %p —— 拒绝（空数组的包「导入成功」后什么都没变，却会被记成升级完成）',
    (images) => {
      const raw = bundleManifest();
      if (images === undefined) delete raw.images;
      else raw.images = images;
      expect(() => policy.parseBundleManifest(raw)).toThrow(/非空数组/);
    }
  );

  test.each([[null], ['payload/app.tar'], [[]], [42]])(
    'images[0] 不是对象 %p —— 拒绝（不能对下标位置放行）',
    (entry) => {
      expect(() => policy.parseBundleManifest(bundleManifest({ images: [entry] }))).toThrow(
        /不是对象/
      );
    }
  );
});

describe('role：只认 app，且同一角色只能声明一次', () => {
  test.each([['db'], ['nginx'], ['app-green'], ['APP'], [''], [undefined]])(
    'role = %p —— 拒绝（多一个角色就要多一条「它凭什么被允许」的判据）',
    (role) => {
      expect(() =>
        policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ role })] }))
      ).toThrow(/role 非法/);
    }
  );

  test('role 重复 —— 拒绝：两条同角色声明会让「实际装哪个」取决于数组顺序', () => {
    const images = [imageEntry(), imageEntry({ file: 'payload/fsms-app-2.tar' })];
    expect(() => policy.parseBundleManifest(bundleManifest({ images }))).toThrow(/role 重复/);
  });

  test('同一份 payload 声明两次 —— 拒绝（load 两遍且由顺序决定赢家；两层去重互为备份）', () => {
    // 当前只有 app 一个角色，重复载荷必然先撞上 role 去重，file 那条因此**不可达**
    // （变异实测：删掉 seenFiles 分支，本套件仍然全绿——它是个等价变异，不是漏测）。
    // 这里对两个判据都接受：要钉住的是「重复声明不被接受」这件事本身；等 IMAGE_ROLES
    // 加上第二个角色，两处去重的先后顺序变化不会让本用例变成假绿。
    const images = [imageEntry(), imageEntry()];
    expect(() => policy.parseBundleManifest(bundleManifest({ images }))).toThrow(
      /role 重复|file 重复/
    );
  });
});

describe('file：只接受包内相对 .tar', () => {
  test.each([
    ['payload/fsms-app.tgz'],
    ['payload/fsms-app.tar.gz'],
    ['payload/fsms-app.zip'],
    ['payload/fsms-app.TAR'],
  ])(
    'file = %s —— 拒绝（docker save 的产物是未压缩 .tar；别的形态等于让导入器自己解释这个文件）',
    (file) => {
      expect(() =>
        policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ file })] }))
      ).toThrow(/docker save 产出的 \.tar/);
    }
  );

  test('file 缺失或不是字符串 —— 拒绝（缺省的 file 等于「不校验路径的 payload」）', () => {
    for (const file of [undefined, 123, null]) {
      expect(() =>
        policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ file })] }))
      ).toThrow(/包内路径为空/);
    }
  });

  test('file 含反斜杠 —— 整个 manifest 拒绝（路径判据必须真的接在 parseBundleManifest 上）', () => {
    expect(() =>
      policy.parseBundleManifest(
        bundleManifest({ images: [imageEntry({ file: 'payload\\fsms-app.tar' })] })
      )
    ).toThrow(/反斜杠/);
  });

  test('file 是包外路径 —— 整个 manifest 拒绝（不能因为其它字段都合规就放过上跳段）', () => {
    expect(() =>
      policy.parseBundleManifest(
        bundleManifest({ images: [imageEntry({ file: '../../app.tar' })] })
      )
    ).toThrow(/爬出包根/);
  });
});

describe('bytes / sha256：声明值缺一个，就等于少一条判据', () => {
  test.each([[0], [-1], [1.5], ['1024'], [null], [undefined], [NaN]])(
    'bytes = %p —— 拒绝（缺省或非正整数会让「比对大小」这一步静默失效）',
    (bytes) => {
      expect(() =>
        policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ bytes })] }))
      ).toThrow(/必须是正整数/);
    }
  );

  test.each([
    [SHA256_A.toUpperCase()],
    [SHA256_A.slice(1)],
    ['z'.repeat(64)],
    [undefined],
    [123],
    [DIGEST_A],
  ])('sha256 = %p —— 拒绝（没有摘要的 payload 等于「不校验的 payload」）', (sha256) => {
    expect(() =>
      policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ sha256 })] }))
    ).toThrow(/64 位小写十六进制/);
  });
});

describe('离线包不是 tag 的逃生通道（最容易被放水的一处）', () => {
  const TAG_REFS = [
    'ghcr.io/qmzzzzz/fsms:v1.2.3',
    'ghcr.io/qmzzzzz/fsms:latest',
    'ghcr.io/qmzzzzz/fsms',
  ];

  test.each(TAG_REFS)(
    'ref = %s —— 整个包拒绝（否则「把包拷到目标机」就等价于「安装任意代码」，而留痕里只有一个 tag 名）',
    (ref) => {
      const msg = messageOf(() =>
        policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ ref })] }))
      );
      expect(msg).toMatch(/digest 钉扎/);
      // 文案要能直接照抄修复
      expect(msg).toMatch(/@sha256:/);
    }
  );

  test('tag 与 digest 并存时以 digest 为准（判据拒绝的是「没有 digest」，不是「字符串里有冒号」）', () => {
    const ref = 'ghcr.io/qmzzzzz/fsms:v1.2.3@' + DIGEST_A;
    const parsed = policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ ref })] }));
    expect(parsed.images[0].digest).toBe(DIGEST_A);
  });

  test('引用里再塞一个 @ —— 拒绝：取最后一个 @ 之前的整段当仓库名，那段过不了仓库名校验', () => {
    const ref = 'ghcr.io/qmzzzzz/fsms@ghcr.io/evil/fsms@' + DIGEST_A;
    expect(() =>
      policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ ref })] }))
    ).toThrow(/镜像仓库名非法/);
  });

  test.each([[''], [undefined], [null]])(
    'ref = %p —— 拒绝（空引用不是「默认用某个镜像」）',
    (ref) => {
      expect(() =>
        policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ ref })] }))
      ).toThrow(/镜像引用为空/);
    }
  );

  test.each([
    ['ghcr.io/qmzzzzz/fsms@sha256:short'],
    ['ghcr.io/qmzzzzz/fsms@sha256:' + 'A'.repeat(64)],
  ])('digest 形态非法 %s —— 拒绝（大写十六进制同样不接受：摘要口径只在一处定义）', (ref) => {
    expect(() =>
      policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ ref })] }))
    ).toThrow(/digest 格式非法/);
  });
});

describe('摘要与大小：自称必须与磁盘上的实际字节对得上', () => {
  test('大小写不同仍算相符（sha256sum / Get-FileHash 产出大写是常态，混成「不符」会让真正的不符淹没在噪音里）', () => {
    expect(policy.assertDigestEqual(SHA256_A, SHA256_A.toUpperCase(), 'payload ' + TAR)).toBe(true);
    expect(policy.assertDigestEqual(SHA256_A.toUpperCase(), SHA256_A, 'payload ' + TAR)).toBe(true);
  });

  test('payload 被替换 —— 报「摘要不符」，且把两个值都写出来（只说「校验失败」等于让人猜）', () => {
    const msg = messageOf(() => policy.assertDigestEqual(SHA256_A, SHA256_B, 'payload ' + TAR));
    expect(msg).toMatch(/摘要不符/);
    expect(msg).toContain(SHA256_A);
    expect(msg).toContain(SHA256_B);
    expect(msg).toContain(TAR);
  });

  test.each([[''], [null], [undefined]])(
    '实际摘要为空 %p —— 报「无法证明是同一份文件」，而不是当成相符',
    (actual) => {
      expect(() => policy.assertDigestEqual(SHA256_A, actual, 'payload ' + TAR)).toThrow(
        /实际摘要为空/
      );
    }
  );

  test('截断的 payload —— 报「大小不符」，并给出声明值与实际值', () => {
    const msg = messageOf(() => policy.assertSizeEqual(4096, 1023, 'payload ' + TAR));
    expect(msg).toMatch(/大小不符/);
    expect(msg).toContain('4096');
    expect(msg).toContain('1023');
  });

  test('大小相符（含字符串形态的声明值）—— 放行，判据不得反向误伤', () => {
    expect(policy.assertSizeEqual(1024, 1024, 'payload ' + TAR)).toBe(true);
    expect(policy.assertSizeEqual(1024, '1024', 'payload ' + TAR)).toBe(true);
  });

  test('恰好等于上限 —— 放行（上限写成 >= 会让 8 GiB 的合法包永远装不上）', () => {
    const cap = policy.DEFAULT_MAX_PAYLOAD_BYTES;
    expect(cap).toBe(8 * 1024 * 1024 * 1024);
    expect(policy.assertWithinCap(cap, cap, 'payload ' + TAR)).toBe(true);
  });

  test('超过上限 —— 拒绝，且文案带上限（运维才知道该调上限还是分包）', () => {
    const cap = policy.DEFAULT_MAX_PAYLOAD_BYTES;
    const msg = messageOf(() => policy.assertWithinCap(cap + 1, cap, 'payload ' + TAR));
    expect(msg).toMatch(/超过上限/);
    expect(msg).toContain(String(cap));
  });
});

describe('白名单：离线包同样不是绕开白名单的通道', () => {
  const parsed = policy.parseBundleManifest(bundleManifest()).images[0];

  test('空白名单 = 全拒（「不知道能装什么」的默认状态必须是「什么都不装」）', () => {
    expect(() => policy.assertBundleImageAllowed(parsed, [])).toThrow(/白名单为空/);
    expect(() => policy.assertBundleImageAllowed(parsed, ['  ', ''])).toThrow(/白名单为空/);
    expect(() => policy.assertBundleImageAllowed(parsed, undefined)).toThrow(/白名单为空/);
  });

  test('命中前缀则放行（正向对照）', () => {
    expect(policy.assertBundleImageAllowed(parsed, ['ghcr.io/qmzzzzz/'])).toBe(true);
    expect(policy.assertBundleImageAllowed(parsed, ['ghcr.io/qmzzzzz/fsms'])).toBe(true);
  });

  test('前缀必须落在路径分隔符上：fsms-evil 不得冒充 fsms', () => {
    const evil = { repository: 'ghcr.io/qmzzzzz/fsms-evil' };
    expect(() => policy.assertBundleImageAllowed(evil, ['ghcr.io/qmzzzzz/fsms'])).toThrow(
      /不在白名单/
    );
  });

  test('前缀比仓库多一段同样不匹配（fsms 不得匹配 fsms/app，反方向也是冒充）', () => {
    expect(() => policy.assertBundleImageAllowed(parsed, ['ghcr.io/qmzzzzz/fsms/app'])).toThrow(
      /不在白名单/
    );
  });

  test('其它组织的镜像被拒', () => {
    const other = { repository: 'ghcr.io/someoneelse/fsms' };
    expect(() => policy.assertBundleImageAllowed(other, ['ghcr.io/qmzzzzz/'])).toThrow(
      /不在白名单/
    );
  });
});

describe('离线判据不是第二套实现（与在线路径逐字同口径）', () => {
  test('非法引用的报错与 hotUpgradePolicy.parseImageRef 完全一致', () => {
    const refs = ['ghcr.io/qmzzzzz/fsms:v1.2.3', '', 'ghcr.io/x/y@sha256:short'];
    for (const ref of refs) {
      expect(
        outcomeOf(() =>
          policy.parseBundleManifest(bundleManifest({ images: [imageEntry({ ref })] }))
        )
      ).toEqual(outcomeOf(() => hotUpgradePolicy.parseImageRef(ref)));
    }
  });

  test('白名单判定与 hotUpgradePolicy.assertImageAllowed 完全一致（离线侧另写一份前缀匹配必然漂移）', () => {
    const parsed = policy.parseBundleManifest(bundleManifest()).images[0];
    const cases = [
      [parsed, []],
      [parsed, ['  ', '']],
      [parsed, ['ghcr.io/qmzzzzz/']],
      [parsed, ['ghcr.io/qmzzzzz/fsms']],
      [{ repository: 'ghcr.io/qmzzzzz/fsms-evil' }, ['ghcr.io/qmzzzzz/fsms']],
      [{ repository: 'ghcr.io/someoneelse/fsms' }, ['ghcr.io/qmzzzzz/']],
    ];
    for (const [img, list] of cases) {
      expect(outcomeOf(() => policy.assertBundleImageAllowed(img, list))).toEqual(
        outcomeOf(() => hotUpgradePolicy.assertImageAllowed(img, list))
      );
    }
  });
});

describe('命令行：未知参数必报错，默认演练', () => {
  test('不给 --apply 就是演练（一次误敲不该产生任何副作用）', () => {
    const opts = policy.parseArgs(['--bundle', '/var/lib/fsms/upgrade/bundles/v1.2.3']);
    expect(opts.apply).toBe(false);
    expect(opts.dryRun).toBe(false);
    expect(opts.help).toBe(false);
    expect(opts.bundle).toBe('/var/lib/fsms/upgrade/bundles/v1.2.3');
    expect(opts.bundleRoot).toBe('');
    expect(opts.allowlist).toBe('');
    expect(opts.maxPayloadBytes).toBe(policy.DEFAULT_MAX_PAYLOAD_BYTES);
  });

  test('布尔旗标 =false/=0/=no 为假，=maybe 报错而不是猜一个', () => {
    expect(policy.parseArgs(['--apply']).apply).toBe(true);
    expect(policy.parseArgs(['--apply=true']).apply).toBe(true);
    expect(policy.parseArgs(['--apply=1']).apply).toBe(true);
    expect(policy.parseArgs(['--apply=false']).apply).toBe(false);
    expect(policy.parseArgs(['--apply=0']).apply).toBe(false);
    expect(policy.parseArgs(['--apply=no']).apply).toBe(false);
    expect(() => policy.parseArgs(['--apply=maybe'])).toThrow(/布尔值/);
    expect(() => policy.parseArgs(['--dry-run=off'])).toThrow(/布尔值/);
  });

  test('内联写法 --bundle=/x 与空格写法等价', () => {
    expect(policy.parseArgs(['--bundle=/x/y']).bundle).toBe('/x/y');
    expect(policy.parseArgs(['--bundle', '/x/y']).bundle).toBe('/x/y');
    expect(policy.parseArgs(['--dry-run']).dryRun).toBe(true);
    expect(policy.parseArgs(['--dry-run=false']).dryRun).toBe(false);
  });

  test('拼错 --bundle-rootz —— 报错，且文案里能照抄到正确拼写', () => {
    // 判据不是「报错就行」：静默忽略时脚本会去默认目录找包，而操作者以为已经指到别处。
    // 文案必须含正确拼写，运维才能不改源码就修好命令。
    //
    // 已知缺口：本仓 scripts/cliFlagPolicy.js 的 suggestFlag 已经把「是否想写 --bundle-root」
    // 这类建议做成了现成件，而 parseArgs 目前只列全部可用开关、不给建议。本用例刻意
    // **不**断言「没有建议」：补上建议后它照样通过，缺口填不填都不制造假红。
    const msg = messageOf(() => policy.parseArgs(['--bundle-rootz', '/var/lib/fsms/upgrade']));
    expect(msg).toMatch(/未知参数/);
    expect(msg).toContain('--bundle-rootz');
    expect(msg).toContain('--bundle-root');
  });

  test('位置参数与单连字符 token 一律拒绝（本脚本没有任何位置参数）', () => {
    expect(() => policy.parseArgs(['production'])).toThrow(/无法识别的参数/);
    expect(() => policy.parseArgs(['-bundle', '/x'])).toThrow(/无法识别的参数/);
  });

  test('缺值报错，而不是把下一个开关当成值', () => {
    expect(() => policy.parseArgs(['--bundle'])).toThrow(/需要一个值/);
    expect(() => policy.parseArgs(['--bundle', '--apply'])).toThrow(/需要一个值/);
    expect(() => policy.parseArgs(['--allowlist', '--apply'])).toThrow(/需要一个值/);
  });

  test.each([['abc'], ['0'], ['-1'], ['1.5'], ['']])(
    '--max-payload-bytes=%s —— 报错（上限被静默忽略时，畸形 manifest 又能把校验变成一次超长磁盘读）',
    (value) => {
      expect(() => policy.parseArgs(['--max-payload-bytes=' + value])).toThrow(/需要正整数/);
    }
  );

  test('--max-payload-bytes 的空格写法同样拒绝非正整数（运维更常这么敲）', () => {
    expect(() => policy.parseArgs(['--max-payload-bytes', 'abc'])).toThrow(/需要正整数/);
    expect(() => policy.parseArgs(['--max-payload-bytes', '-1'])).toThrow(/需要正整数/);
  });

  test('--max-payload-bytes 合法值按字节数生效', () => {
    expect(policy.parseArgs(['--max-payload-bytes', '1048576']).maxPayloadBytes).toBe(1048576);
    expect(policy.parseArgs(['--max-payload-bytes=1024']).maxPayloadBytes).toBe(1024);
  });

  test('开关集合是闭合清单：新增开关必须在这里显式确认（清单写死在这里是故意的）', () => {
    expect(policy.FLAGS).toEqual([
      'bundle',
      'bundle-root',
      'allowlist',
      'max-payload-bytes',
      'apply',
      'dry-run',
      'help',
    ]);
  });
});

describe('白名单拆分与常量', () => {
  test('逗号分隔会去空白与空项', () => {
    expect(policy.splitAllowlist(' ghcr.io/a/ , ,ghcr.io/b/ ')).toEqual([
      'ghcr.io/a/',
      'ghcr.io/b/',
    ]);
  });

  test('未配置 —— 空数组（不是「未配置＝不限」）', () => {
    expect(policy.splitAllowlist('')).toEqual([]);
    expect(policy.splitAllowlist(undefined)).toEqual([]);
  });

  test('格式版本 1、角色只有 app、单个 payload 上限 8 GiB', () => {
    expect(policy.BUNDLE_FORMAT_VERSION).toBe(1);
    expect(policy.IMAGE_ROLES).toEqual(['app']);
    expect(policy.DEFAULT_MAX_PAYLOAD_BYTES).toBe(8 * 1024 * 1024 * 1024);
  });
});
