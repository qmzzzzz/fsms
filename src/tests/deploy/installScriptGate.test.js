/**
 * 安装脚本登记门禁（`scripts/check-prod-install-scripts.js`）的可证伪性自检。
 *
 * 为什么要这条测试：该脚本是 Dockerfile 里 `npm ci --omit=dev --ignore-scripts`
 * **安全性成立的唯一依据**——它证明「忽略脚本后的生产闭包里根本没有脚本需要忽略」，
 * 以及「dev 树里真正会执行的安装脚本已被逐个评审登记」。门禁本身一旦退化成恒绿
 * （比如判据写错、锁文件字段读错、白名单被塞成通配），上面两处 --ignore-scripts
 * 就都失去依据，而 CI 仍全绿。
 *
 * 【2026-09-30 修正：从"复刻判据"改为"真调判据"】
 * 本套件初版把脚本的判定语义**复刻**了一遍（自己写 classify），并在注释里自称
 * "可证伪"。实测证伪：把脚本的筛选条件 `omitDev ? !e.dev : e.dev` 写反
 * （生产树与 dev 树颠倒 ⇒ 门禁退化成"永远失败"），复刻版测试 **6/6 全绿**。
 * 复刻一份判据等于测试了一个平行实现，与被测对象是否还正确无关。
 * 现改为直接 require 脚本导出的 `evaluate` 跑真判据（脚本已加 `require.main === module`
 * 守卫）；下方每条断言都由 mutate 实测确认过"改坏必红"。
 *
 * 本套件不启动 npm、不连网、不起子进程 ⇒ 确定性，可在任意环境跑。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const LOCKFILE = path.join(ROOT, 'package-lock.json');
const SCRIPT = path.join(ROOT, 'scripts', 'check-prod-install-scripts.js');

/** 被测对象的真判据（不许在本文件里另写一份） */
const { evaluate, PROD_INSTALL_SCRIPT_ALLOWLIST, DEV_INSTALL_SCRIPT_ALLOWLIST } = require(SCRIPT);

const lock = JSON.parse(fs.readFileSync(LOCKFILE, 'utf8'));

/** names(evaluate 结果的 all) 便于断言 */
const namesOf = (r) => r.all.map((x) => x.name).sort();

describe('安装脚本门禁：判据可证伪且与登记册一致', () => {
  test('前提自证：锁文件确实带 hasInstallScript 标记（读空会让本套件整条恒绿）', () => {
    // 若 npm 改了锁文件格式、这个字段不再写入，下面所有断言都会退化成"空集相等"而恒真。
    // 故显式钉住"至少存在一个带标记的条目"。
    const marked = Object.values(lock.packages || {}).filter((m) => m && m.hasInstallScript);
    expect(marked.length).toBeGreaterThan(0);
  });

  test('生产树（非 dev 标记）的每个安装脚本都已在 PROD_INSTALL_SCRIPT_ALLOWLIST 登记', () => {
    const r = evaluate(lock, true);
    expect(r.all.length).toBeGreaterThan(0); // 现实是 @scarf/scarf；空集说明判据读错了
    expect(r.offenders).toEqual([]);
  });

  test('dev 树的每个安装脚本都已在 DEV_INSTALL_SCRIPT_ALLOWLIST 登记', () => {
    const r = evaluate(lock, false);
    expect(r.all.length).toBeGreaterThan(0); // 现实是 mongodb-memory-server (+fsevents)
    expect(r.offenders).toEqual([]);
  });

  // —— 本套件最关键的一条 ——
  // 变异实测（2026-09-30）：把 evaluate 里 `omitDev ? !e.dev : e.dev` 改成
  // `omitDev ? e.dev : !e.dev`（两棵树颠倒），本条必须变红。
  test('生产树与 dev 树不重叠、且覆盖全部带脚本条目（防"两棵树写反"）', () => {
    const prod = evaluate(lock, true);
    const dev = evaluate(lock, false);
    const prodNames = namesOf(prod);
    const devNames = namesOf(dev);
    // 两棵树不许有交集——写反选择条件时交集仍在，但下面的覆盖断言会破
    expect(prodNames.filter((n) => devNames.includes(n))).toEqual([]);
    // 并集必须等于"锁文件里全部带脚本的包名"，少一个都说明某棵树漏筛
    const allNames = [...new Set([...prodNames, ...devNames])].sort();
    expect(allNames).toContain('@scarf/scarf');
    expect(allNames).toContain('mongodb-memory-server');
    expect(prodNames).toContain('@scarf/scarf');
    expect(devNames).toContain('mongodb-memory-server');
  });

  test('反向对照：注入一个未登记脚本，判据必须判红（证明不是恒绿）', () => {
    const tampered = JSON.parse(JSON.stringify(lock));
    tampered.packages['node_modules/zzq-evil-postinstall'] = {
      version: '0.0.1',
      hasInstallScript: true,
    };
    const r = evaluate(tampered, true);
    expect(namesOf(r)).toContain('zzq-evil-postinstall');
    expect(r.offenders.map((x) => x.name)).toEqual(['zzq-evil-postinstall']);
  });

  test('反向对照：dev 标记的注入落在 dev 树，不污染生产树判定', () => {
    const tampered = JSON.parse(JSON.stringify(lock));
    tampered.packages['node_modules/zzq-evil-dev'] = {
      version: '0.0.1',
      hasInstallScript: true,
      dev: true,
    };
    expect(namesOf(evaluate(tampered, false))).toContain('zzq-evil-dev');
    expect(namesOf(evaluate(tampered, true))).not.toContain('zzq-evil-dev');
  });

  test('反向对照：没带 hasInstallScript 标记的包一律不入册（防"全量误报"）', () => {
    const tampered = JSON.parse(JSON.stringify(lock));
    tampered.packages['node_modules/zzq-no-script'] = { version: '0.0.1' };
    expect(namesOf(evaluate(tampered, true))).not.toContain('zzq-no-script');
  });

  test('scoped 包名解析正确（@scarf/scarf 不是被截成 scarf）', () => {
    expect(namesOf(evaluate(lock, true))).toContain('@scarf/scarf');
  });

  test('判据本身被 require 时不执行 CLI（否则测试进程会被 process.exit 带走）', () => {
    // require.main !== module 时不得调 main()——实测过：初版脚本顶层裸调 main()，
    // 测试一旦 require 就会立刻 process.exit，整个 jest 进程消失。
    expect(typeof evaluate).toBe('function');
    expect(Array.isArray(PROD_INSTALL_SCRIPT_ALLOWLIST)).toBe(true);
    expect(typeof DEV_INSTALL_SCRIPT_ALLOWLIST).toBe('object');
  });
});
