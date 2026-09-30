/**
 * Jest 配置文件
 * 集中管理测试环境、模块映射、覆盖率等
 */

module.exports = {
  // Node 环境（与 jsdom 区别）
  testEnvironment: 'node',

  // 测试匹配规则
  testMatch: ['**/src/tests/**/*.test.js'],

  // 全局 setup：使用 mongodb-memory-server 启动内存 MongoDB
  globalSetup: '<rootDir>/src/tests/globalSetup.js',
  globalTeardown: '<rootDir>/src/tests/globalTeardown.js',

  // 每个测试文件运行前同步设置环境变量
  setupFiles: ['<rootDir>/src/tests/setup.js'],

  // 每个测试用例的默认超时（毫秒）
  testTimeout: 30000,

  // 覆盖率收集配置
  collectCoverageFrom: [
    'src/**/*.js',
    // 测试基建不得进生产覆盖率分母（2026-09-21 实测：`src/**/*.js` 会把 src/tests/ 一起收进来，
    // lcov 140 个文件里有 4 个是测试基建）。危害是双向的，且都不止"数字难看"：
    //   · `src/tests/deploy/helpers/stubExec.js` 实测 fn 0/14、br 0/46、line 0/79 ——
    //     一个**0% 覆盖的测试替身**算进生产分母，等于凭空压住全局水位；
    //   · `src/tests/helpers/buildLoginEnvelope.js` 等 3 个则接近 100%，反向**抬高**水位。
    // 净效果（剔除后 vs 含）：branches +0.64pt、functions +0.94pt、lines +0.81pt。
    // 真正的问题是口径：生产覆盖率的分母必须只含生产代码，否则"给测试桩写用例"
    // 也能让门禁变绿。防再漂移闸见 tests/deploy 里的 ciGateWiring 套件。
    '!src/tests/**',
    '!src/index.js', // 排除应用入口
    '!src/config/database.js', // 排除数据库连接
    '!src/docs/generate.js', // 排除 Swagger 文档生成脚本（独立工具，非运行时代码）
    // E-03 整改：validate.js 与 initData.js 已纳入统计（并在下方单独设阈值）。
    // 这两个文件此前被整体排除，导致约 2,000 行生产代码「不可见」——
    // initData.js 每次启动都执行权限播种与超管唯一性对账，是安全相关逻辑，
    // 排除在覆盖率之外等于默认它不会劣化。纳入后先「看见」真实水位，
    // 再按棘轮逐档补测（两者当前水位偏低，见下方阈值注释）。
  ],

  coverageDirectory: 'coverage',

  // lcov 供 CI codecov 上传（T-3 硬门禁），缺了它门禁形同虚设
  coverageReporters: ['text-summary', 'text', 'lcov'],

  // 覆盖率阈值 —— 棘轮（ratchet）策略（I-03 / P3-49，2026-09-20 调整方向）
  //
  // 目标不变：安全关键模块 branches/functions 逼近 80%+。变的是**用哪把尺子**。
  // 覆盖率衡量的是"有没有被执行到"，不是"有没有被断言"——2026-09-20 对 36 个
  // 独立阈值文件逐个对账（数据源＝当轮 `npm run test:coverage` 的 lcov），两极同时存在：
  //   · 贴面 23 个（min Δ < 3pt，其中 8 个 Δ ≤ 1pt）：阈值贴着实测 ⇒ 加一个与测试
  //     无关的分支就红灯，开发者的理性选择是写"只打分支不断言"的用例解锁。
  //     这条因果链有实证：2026-09-15 新增的 `controllers/coverageDebt.test.js` 文件头
  //     自述"本轮给三个文件新增了分支，导致 coverageThreshold 跌破基线，CI 挂掉"，
  //     而它的用例"只断言分支落点，不重复端到端语义"——正是这条链的产物。
  //     （该文件已于 09-21~09-26 的用例整合中并入语义化命名的套件，接管关系写在
  //      `controllers/inspectionScopeAndSensitiveViewGuards.test.js:38-40`。此处原先
  //      直接指向那个已删除的路径，是条死引用，2026-09-28 更正为可复现的出处。）
  //     **阈值本身成了弱测试的制造机。**
  //   · 过松 16 个（max Δ > 8pt，最松 reportController +29pt）：批量删用例 CI 仍绿。
  //
  // 处置（2026-09-20）：只**下调**贴面的一侧到统一余量——branches 取「实测 -5pt」、
  // functions 取「实测 -3pt」，向下取整，且**绝不上调**任何一项；余量本来就够的文件不动。
  // 那一轮把过松的一侧刻意留高不动，理由是"抬阈值只会催生更多假用例，先把尺子
  // 换成可证伪性再谈水位"。
  //
  // 处置（2026-09-28）：把**同一把尺子铺到过松的一侧**。只动贴面一侧的结果是过松侧
  // 长期不收敛——2026-09-28 对 36 条的实测对账显示余量仍达 8~32pt（最松
  // authController branches +32pt、deviceController +29.7pt、reportController +29.7pt），
  // 等于"删掉一整批用例 CI 仍绿"。本轮规则（逐指标独立判断，只上调、绝不下调）：
  //   · 实测 - 现值 > 8pt ⇒ 收紧到 floor(实测 - 5)（branches）/ floor(实测 - 3)（functions）；
  //   · ≤ 8pt ⇒ 不动。这一档里含几处**时序敏感**项（auditMonitor 的 br、
  //     deviceReminder 的 br、sessionService 的 br），它们的余量是刻意留的，
  //     压缩只会换来 flaky。
  // 与 2026-09-20 那一轮合并后，全文只剩**一条**规则：
  //   「每条阈值 = 实测下方 5pt(分支) / 3pt(函数)，向下取整；上限为实测值，只紧不松」。
  //
  // 【本轮实测证据，必须与上面的结论一起读】
  //   · 量出来的"单个测试文件值多少"：`statsCache.js` 分支 96.42%，删掉它的专属测试
  //     文件后降到 92.85% —— **单个测试文件只值约 3.6pt**。所以 -5pt 余量把"可删量"
  //     从 26.4pt 压到 5.4pt（约 7 倍），但**仍拦不住"只删那一个专属测试文件"**。
  //     要让单文件删除也判红，余量得压到 3pt 以下——那正是上面被否掉的贴面形态。
  //   · 所以这里的阈值是**回归绊线**，不是"测试还在不在"的证明。后者要靠测试清单
  //     对账与变异（可证伪性）两条腿，别指望一个百分比。
  //   · 本轮收紧的 24 个文件已逐个核对：**不含任何 `process.platform` 分支**，
  //     故与 CI 的 Linux 平台之间不存在平台性覆盖率差异（本机 win32 实测可用）。
  //   · 本文件仍然**不写死**实时覆盖率数字；要当前值跑 `npm run test:coverage`。
  //
  // 真正的尺子＝**可证伪性**：往被测源码注入一个 bug（守卫取反 / 比较符挪档 /
  // 常量真假互换 / throw 整句删除），定向跑该文件的用例集；不红＝这条用例没在设防。
  // 批次 3（70ff0bc）已按此把 6 处"绿但不设防"的用例改回可证伪，本轮把同一把尺子
  // 铺到全部 36 个文件。用例去留按这个判据逐条定，**不做批量删除**。
  //
  // P3-49 历史：基线曾长期贴着旧实测（2026-08-23），拉开 10~46pt 后形同虚设，
  // 2026-08-27 按全量实测重设过一轮——那一轮的"只上调不下调"纪律就是上面贴面问题的来源。
  coverageThreshold: {
    // 【口径说明】本文件只锁阈值，不记录实时覆盖率数字——
    // 此前注释里写死的实测快照（如 st 89.94 / br 77.72）会随代码演进失实，
    // 反而误导（报告 §10.5 漂移 #11）。需要当前数字请跑 `npm run test:coverage`。
    //
    // 注意 global 分组**不含**下方单独设阈值的文件——Jest 会把它们从 global
    // 组里摘出去，因此 global 数字与 text-summary 的总计不同。
    // 基线按分组后的真实值取，否则会莫名红灯。
    global: {
      branches: 79,
      functions: 87,
      lines: 91,
      statements: 91,
    },
    // 安全关键模块：基线按 2026-09-20 全量实测留统一余量重设（br -5pt / fn -3pt，只下调）。
    // 逐行的"(实测 a/b)"快照注释已全部删除——上方口径说明明确禁止在本文件写死实时数字，
    // 而实测确有 33/36 条与当轮真值相差 >1pt（最大 validate.js 注释 75 vs 实测 93.97）。
    // 要当前数字跑 `npm run test:coverage`。
    './src/middleware/security.js': { branches: 88, functions: 84 },
    './src/middleware/rateLimit.js': { branches: 77, functions: 97 }, // 2026-09-10 makeSharedStore改为同步代理包装器
    // 【2026-09-30 修正：functions 97 → 90】原值 97 是 aa92bb7（2026-09-28）按
    // 「实测 - 3pt」机械套用时**误按"实测 100%"推导**出来的，而 auth.js 的函数
    // 覆盖率实际是 **93.33%（14/15）**。证据链：
    //   · aa92bb7 版 auth.js 与当前版本**代码逐字节相同**（仅差 5301834 改名带出的
    //     一行注释路径 `zzqoder_populateMatchShape` → `populateMatchShape`），
    //     函数计数同为 15 ⇒ 93.33% 自那时起就是真值，97 从未可达。
    //   · 唯一未覆盖的函数是 `auth.js:178-185` 的 30s 用户缓存清理 setInterval 回调，
    //     且这是**有意的、有据可查的**取舍——src/tests/middleware/
    //     authMiddlewareFailClosedGuards.test.js:40-42 记明「不做覆盖……强行驱动需
    //     伪造系统时钟，与 mongodb 驱动冲突（见 permCacheLifecycle.test.js 实测）」。
    //   · 同族先例：本文件下方 `auditMonitor.js` 的 `functions: 78` 同样以
    //     「fn 受 interval 回调/unref 行(91-92)未触达拖累」为由留低。
    //   ⇒ 这不是"回归导致跌破"，而是**阈值本身推导错误**：按本文件唯一规则
    //     `floor(实测 - 3)` 应得 `floor(93.33 - 3) = 90`。
    // 为何长期未暴露：CI 的 step 13「Run tests with coverage」在 #72–#75 都被前序
    // step 11/12 的红灯 skip/cancel，从未真正执行；2026-09-30 修好 step 11/12 后
    // 才第一次跑到，于是这条**自写下之日起就不可能通过**的阈值第一次现形。
    // 修正后仍是有意义的绊线：实测 93.33 vs 阈值 90，再丢 1 个函数（→86.67）即转红。
    './src/middleware/auth.js': { branches: 87, functions: 90 },
    './src/middleware/tokenBlacklist.js': { branches: 82, functions: 97 },
    './src/middleware/rbac.js': { branches: 88, functions: 93 },
    // 2026-08-28 pureModules.test.js 补 DataMasking/HMAC/HashUtils/AES 缺口
    './src/utils/encryption.js': { branches: 89, functions: 95 },
    './src/utils/auditChain.js': { branches: 83, functions: 97 },
    // 2026-08-28 批次 B（authLifecycle/authRest）后实测
    './src/controllers/authController.js': { branches: 91, functions: 77 },
    // 2026-08-28 securityQuick/securityDeep 后实测
    './src/controllers/securityController.js': { branches: 86, functions: 93 },
    // 设备级会话管理（登录会话）：新增模块，随功能一并补齐了
    // sessionService.test.js（39 例）与 sessionManagement.test.js（18 例）。
    //
    // 单独设阈值而非并入 global 有两个理由：
    //  1. 会话服务是「踢除单台设备」的唯一事实来源，它退化的表现不是报错
    //     而是安全结论错误（用户以为踢掉了设备，对方其实还在线），
    //     必须有独立门槛而不能被 global 的平均值稀释；
    //  2. 新模块并入 global 会改变分母，让一个与本次改动无关的基线红灯。
    // 这两个模块起点就接近 100%，直接按 80% 硬门槛之上取值。
    './src/services/sessionService.js': { branches: 87, functions: 97 },
    './src/models/UserSession.js': { branches: 75, functions: 97 },
    // ===== 2026-08-28 冲覆盖率批次新增基线 =====
    './src/services/DeviceService.js': { branches: 78, functions: 97 },
    './src/services/AlarmService.js': { branches: 82, functions: 97 },
    './src/services/InspectionService.js': { branches: 80, functions: 97 },
    './src/services/userPermissionService.js': { branches: 82, functions: 88 },
    './src/services/statsCache.js': { branches: 91, functions: 88 },
    './src/services/auditMonitor.js': { branches: 90, functions: 78 }, // 2026-09-02 时区口径回归批次；fn 受 interval 回调/unref 行(91-92)未触达拖累，br 历史时序敏感故留余量
    './src/services/deviceReminder.js': { branches: 90, functions: 97 }, // 2026-09-04 deviceReminder 分支补齐批次
    './src/middleware/errorHandler.js': { branches: 84, functions: 97 },
    './src/controllers/deviceController.js': { branches: 76, functions: 97 },
    './src/controllers/alarmController.js': { branches: 82, functions: 97 },
    './src/controllers/inspectionController.js': { branches: 92, functions: 97 },
    './src/controllers/roleController.js': { branches: 89, functions: 96 }, // 2026-09-04 按实测下方一档
    './src/controllers/userController.js': { branches: 85, functions: 97 },
    './src/controllers/permissionController.js': { branches: 79, functions: 97 },
    './src/controllers/reportController.js': { branches: 89, functions: 97 }, // 2026-09-04 reportController 分支补齐批次
    './src/services/websocketService.js': { branches: 82, functions: 90 },
    // ===== 2026-09-01 安全服务洼地补齐批次新增基线 =====
    //（authServiceGapA/B/C + securityPrimitivesGap + captchaGap + permissionHelperGap）
    './src/services/authService.js': { branches: 87, functions: 73 },
    './src/services/mfaService.js': { branches: 88, functions: 91 },
    './src/services/captchaService.js': { branches: 75, functions: 87 },
    './src/utils/permissionHelper.js': { branches: 83, functions: 97 }, // 2026-09-04 按实测下方一档
    './src/services/auditChainVerify.js': { branches: 90, functions: 97 }, // 2026-09-04 审计链校验直连单测批次
    './src/services/tokenService.js': { branches: 77, functions: 97 },
    // ===== 2026-09-16 E-03 整改：此前被 collectCoverageFrom 整体排除的两个文件，
    // 纳入统计并单独设阈值。基线按「2026-09-16 实测下方一档」取值——
    // 不是因为它们安全重要度低，而是先让水位可见，再按棘轮逐档补测。
    // 独立设阈的另一个作用：Jest 会把它们从 global 分组摘出，
    // 使「新增被排除文件」不会误伤与之无关的全局基线。
    './src/config/validate.js': { branches: 90, functions: 97 }, // 生产配置校验，此前整体排除
    './src/services/initData.js': { branches: 91, functions: 97 }, // 2026-09-18 initDataLifecycle.test.js 批次（行/语句/函数 100%）
    // 分支 95% 是当前可达上限：剩余 5 个未命中分支经穷举验证为**数据决定的结构不可达**
    // ——initData.js 的 defaultPermissions 每条 code 都含 ":"（:551 的 else 走不到）、
    // defaultRoles 每项都 isBuiltIn:true（:634 的 else）、rolePermissionMap 的键集
    // 与 defaultRoles 的 code 集完全一致且每项非空（:610/:612/:621 的 `|| []`）。
    // 基线取实测下方一档，与本源「实测下方一档」规则一致。
    // ===== 2026-09-16 第四轮：M-05 信任根的独立门槛 =====
    // filePermission.js 是「密钥载体权限已收紧」这一结论的唯一来源（M-05 修复的
    // 落点）。它在第三轮落地时**没有独立阈值**，违反本文件上文自订的规则
    // （「修改/新增安全模块代码必须附带测试，并设独立基线」）——实测当时仅
    // 行 67.34% / 分支 68.42%，失败路径（icacls 执行失败、USERNAME 缺失、
    // 读取失败 fail-closed）全部未被任何测试触达。第四轮补测后实测
    // 行 100% / 分支 97.37%（唯一未覆盖的 `|| ''` 分支经穷举验证为结构不可达：
    // trim() 后 split(/s+/).pop() 必含非空白字符）。
    // 基线取「实测下方一档」；分支留 2pt 余量是因为该分支依赖 icacls 输出解析，
    // 未来若新增解析形态，余量可吸收格式差异而不误红灯。
    './src/utils/filePermission.js': { branches: 92, functions: 97 },
  },

  // 测试文件命名约定
  // web-admin 有独立的 vitest 测试体系（ESM），与本 jest(CJS) 运行时不兼容，必须排除
  testPathIgnorePatterns: ['/node_modules/', '/coverage/', '/web-admin/'],

  // 在每个测试后输出测试计数
  verbose: true,

  // 默认每个测试文件独立 Node 进程（避免状态污染）
  // 关闭以加速测试，但要求测试自身做好隔离
  maxWorkers: '50%',

  // 每个 worker 累计用到该阈值就换新进程（jest 29 支持）。
  // 为什么必须设：本仓每个测试文件都会起内存 MongoDB，worker 常驻内存只增不减；
  // 实测 4.4GB 可用内存的机器上跑全量（280 套 / 3300+ 例）会出现
  // `A jest worker process was terminated by another process: signal=SIGTERM`
  // ——一次跑挂 9 个套件，而被"挂"的套件单独重跑全部通过（即门禁自身在偶发假红）。
  // 验证门禁不稳，等于所有"可证伪"结论都失去可信度，故按内存而非按 CPU 限流。
  workerIdleMemoryLimit: '512MB',

  // 控制台输出
  silent: false,
};
