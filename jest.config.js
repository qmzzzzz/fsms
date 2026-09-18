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

  // 覆盖率阈值 —— 棘轮（ratchet）策略（I-03 / P3-49）
  //
  // 目标：安全关键模块 branches/functions ≥ 80%。
  // 做法：基线始终贴着「当前实测值」下方一档，只上调不下调。
  // 这样它能拦住真实退化（删测试、加未覆盖分支），又不会因为差距过大
  // 而被整体忽视——一个永远红灯的门槛等于没有门槛。
  //
  // P3-49：原基线是 2026-08-23 的实测值，此后多轮修复补了大量测试，
  // 基线与实测已拉开 10~46 个百分点（如 rbac.js 基线 17% 实测 63.63%、
  // tokenBlacklist.js 基线 25% 实测 87.5%）。差距这么大的门槛形同虚设：
  // 可以删掉三分之二的测试而 CI 依然全绿。现按 2026-08-27 全量实测重设。
  //
  // 规则：修改/新增安全模块代码必须附带测试；每次补齐测试后把对应基线
  // 上调到新实测值下方一档，逐档逼近 80% 后恢复硬门槛。
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
    // 安全关键模块：括号内为 2026-09-02 全量实测，基线按「实测下方一档」
    // 重设（显示值为整数的再降 1 档，防精确值四舍五入误伤）
    './src/middleware/security.js': { branches: 67, functions: 84 }, // (67.51/84.61)
    './src/middleware/rateLimit.js': { branches: 78, functions: 85 }, // (78.12/85.18) 2026-09-10 makeSharedStore改为同步代理包装器
    './src/middleware/auth.js': { branches: 90, functions: 87 }, // (90.32/87.5)
    './src/middleware/tokenBlacklist.js': { branches: 87, functions: 100 }, // (87.50/100)
    './src/middleware/rbac.js': { branches: 72, functions: 79 }, // (72.72/80)
    // 2026-08-28 pureModules.test.js 补 DataMasking/HMAC/HashUtils/AES 缺口
    './src/utils/encryption.js': { branches: 82, functions: 95 }, // (82.17/95.83)
    './src/utils/auditChain.js': { branches: 87, functions: 100 }, // (87.17/100)
    // 2026-08-28 批次 B（authLifecycle/authRest）后实测
    './src/controllers/authController.js': { branches: 64, functions: 63 }, // (64.13/63.15)
    // 2026-08-28 securityQuick/securityDeep 后实测
    './src/controllers/securityController.js': { branches: 91, functions: 93 }, // (91.52/93.54)
    // 设备级会话管理（登录会话）：新增模块，随功能一并补齐了
    // sessionService.test.js（39 例）与 sessionManagement.test.js（18 例）。
    //
    // 单独设阈值而非并入 global 有两个理由：
    //  1. 会话服务是「踢除单台设备」的唯一事实来源，它退化的表现不是报错
    //     而是安全结论错误（用户以为踢掉了设备，对方其实还在线），
    //     必须有独立门槛而不能被 global 的平均值稀释；
    //  2. 新模块并入 global 会改变分母，让一个与本次改动无关的基线红灯。
    // 这两个模块起点就接近 100%，直接按 80% 硬门槛之上取值。
    './src/services/sessionService.js': { branches: 91, functions: 100 }, // (91.2/100)
    './src/models/UserSession.js': { branches: 59, functions: 100 }, // (60/100)
    // ===== 2026-08-28 冲覆盖率批次新增基线 =====
    './src/services/DeviceService.js': { branches: 78, functions: 100 }, // (78.57/100)
    './src/services/AlarmService.js': { branches: 73, functions: 100 }, // (73.07/100)
    './src/services/InspectionService.js': { branches: 71, functions: 100 }, // (71.42/100)
    './src/services/userPermissionService.js': { branches: 87, functions: 91 }, // (87.8/91.66)
    './src/services/statsCache.js': { branches: 70, functions: 88 }, // (70.83/88.88)
    './src/services/auditMonitor.js': { branches: 90, functions: 66 }, // (95.83/66.66) 2026-09-02 时区口径回归批次；fn 受 interval 回调/unref 行(91-92)未触达拖累，br 历史时序敏感故留余量
    './src/services/deviceReminder.js': { branches: 90, functions: 80 }, // (97.43/90.9) 2026-09-04 deviceReminder 分支补齐批次
    './src/middleware/errorHandler.js': { branches: 76, functions: 100 }, // (76.66/100)
    './src/controllers/deviceController.js': { branches: 52, functions: 92 }, // (52.94/92.85)
    './src/controllers/alarmController.js': { branches: 80, functions: 100 }, // (80.76/100)
    './src/controllers/inspectionController.js': { branches: 77, functions: 100 }, // (77.14/100)
    './src/controllers/roleController.js': { branches: 86, functions: 96 }, // (86.89/96.96) 2026-09-04 按实测下方一档
    './src/controllers/userController.js': { branches: 64, functions: 87 }, // (64.37/87.5)
    './src/controllers/permissionController.js': { branches: 60, functions: 88 }, // (61/88.88)
    './src/controllers/reportController.js': { branches: 65, functions: 85 }, // (72.24/88) 2026-09-04 reportController 分支补齐批次
    './src/services/websocketService.js': { branches: 81, functions: 91 }, // (81.61/91.17)
    // ===== 2026-09-01 安全服务洼地补齐批次新增基线 =====
    //（authServiceGapA/B/C + securityPrimitivesGap + captchaGap + permissionHelperGap）
    './src/services/authService.js': { branches: 91, functions: 73 }, // (91.16/73.52)
    './src/services/mfaService.js': { branches: 82, functions: 63 }, // (82.35/63.63)
    './src/services/captchaService.js': { branches: 79, functions: 87 }, // (79.41/87.5)
    './src/utils/permissionHelper.js': { branches: 85, functions: 100 }, // (85.41/100) 2026-09-04 按实测下方一档
    './src/services/auditChainVerify.js': { branches: 80, functions: 100 }, // (86.11/100) 2026-09-04 审计链校验直连单测批次
    './src/services/tokenService.js': { branches: 77, functions: 100 }, // (77.77/100)
    // ===== 2026-09-16 E-03 整改：此前被 collectCoverageFrom 整体排除的两个文件，
    // 纳入统计并单独设阈值。基线按「2026-09-16 实测下方一档」取值——
    // 不是因为它们安全重要度低，而是先让水位可见，再按棘轮逐档补测。
    // 独立设阈的另一个作用：Jest 会把它们从 global 分组摘出，
    // 使「新增被排除文件」不会误伤与之无关的全局基线。
    './src/config/validate.js': { branches: 74, functions: 79 }, // (75/80) 生产配置校验，此前整体排除
    './src/services/initData.js': { branches: 94, functions: 99 }, // (95/100) 2026-09-18 initDataLifecycle.test.js 批次（行/语句/函数 100%）
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
    './src/utils/filePermission.js': { branches: 95, functions: 100 }, // (97.37/100)
  },

  // 测试文件命名约定
  // web-admin 有独立的 vitest 测试体系（ESM），与本 jest(CJS) 运行时不兼容，必须排除
  testPathIgnorePatterns: ['/node_modules/', '/coverage/', '/web-admin/'],

  // 在每个测试后输出测试计数
  verbose: true,

  // 默认每个测试文件独立 Node 进程（避免状态污染）
  // 关闭以加速测试，但要求测试自身做好隔离
  maxWorkers: '50%',

  // 控制台输出
  silent: false,
};
