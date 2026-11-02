/**
 * 敏感字段出口契约（P2-1 serializer 层收口，2026-11-02）
 *
 * 背景：审计（参考项目研读 P2-1）指出 fsms 缺少「API 输出字段收口」的统一
 * 契约——实际摸底结论是机制已存在（User 的字段表驱动 RESPONSE_EXCLUDE 双变体、
 * UserSession 的 toClientJSON 白名单、AuditLog 的 RESPONSE_EXCLUDE），但**分散
 * 在各模型、无统一判据**：新增一个带敏感字段的模型时，没有任何门禁会问
 * 「它的对外出口策略是什么」。本文件把这条隐式约定变成红绿可见的显式契约。
 *
 * 判据（对 `select: false` 字段的模型逐个应答）：
 *   A. 该模型声明了 RESPONSE_EXCLUDE（投影式收口），或
 *   B. 提供白名单式出口方法（toClientJSON 等），或
 *   C. 在 EXEMPTIONS 里登记豁免理由（无对外读路径 / select:false 已足够）。
 * 三者皆无 ⇒ 红：新模型引入了默认隐藏字段却没有出口策略，正是本门禁要拦的形态。
 *
 * 为什么用 `select: false` 作判据源：它是本仓「该字段默认不该出现在响应里」
 * 的既有标记物（User 的 11 个字段、Role 的删除恢复标记、UserAvatar 的密文
 * 数据都以此声明）。以它作触发点，等于跟着既有的安全声明走，不需要新引入
 * 一套「敏感字段」标注体系。
 */
const fs = require('fs');
const path = require('path');

const MODELS_DIR = path.join(__dirname, '../../models');

/**
 * 显式豁免登记：这些模型的 select:false 字段无需投影/白名单出口。
 * 每条必须写理由——「豁免必须写明理由」是本仓既定纪律（同 auditLog.js 的
 * a-e 分类注释）。
 */
const EXEMPTIONS = {
  'Role.js':
    '两个 select:false 字段是删除流程的中断恢复标记（deletionPreviousStatus/' +
    'deletionStartedAt），性质是内部状态而非凭证；select:false 已挡住默认读路径，' +
    '且角色读接口不需要这两个字段（恢复对账在启动期直读）。',
  'UserAvatar.js':
    'data 是头像密文（明文为图片 Base64），对外出口只有 GET /api/avatars/:id 的' +
    "二进制回放（avatarService 显式 select('+data')）；hash 走 ETag/URL 版本号，" +
    '二者都不是「模型文档直出响应」的路径，故无 RESPONSE_EXCLUDE 需求。',
};

/** 白名单式出口：模型内定义的 toClientJSON / serialize 方法名 */
const WHITELIST_SERIALIZER = /methods\.(toClientJSON|serialize)\s*=/;

/**
 * 安全的模型文件读取：只接受纯 basename（拒绝路径分隔与跳段），并把解析结果
 * 校验在 MODELS_DIR 之内——文件名全部来自 readdirSync 或常量登记表，
 * 边界校验是防未来有人把外部输入接进来的兜底。
 */
const readModel = (file) => {
  if (!/^[A-Za-z0-9_.-]+$/.test(file) || file.startsWith('.')) return null;
  const full = path.resolve(MODELS_DIR, file);
  if (!full.startsWith(MODELS_DIR + path.sep)) return null;
  return fs.readFileSync(full, 'utf8');
};

const listModelFiles = () =>
  fs
    .readdirSync(MODELS_DIR, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.js') && e.name !== 'index.js')
    .map((e) => e.name)
    .sort();

/** 模型是否有默认隐藏字段（select: false） */
const hasHiddenFields = (src) => /select:\s*false/.test(src);

/** 模型是否声明了投影式收口（静态 RESPONSE_EXCLUDE，含派生态） */
const hasProjection = (src) => /statics\.RESPONSE_EXCLUDE\w*\s*=/.test(src);

/** 模型是否提供白名单式出口方法 */
const hasWhitelistSerializer = (src) => WHITELIST_SERIALIZER.test(src);

describe('敏感字段出口契约（P2-1）：select:false 的模型必须有出口策略或豁免登记', () => {
  const files = listModelFiles();

  test('前提自证：确实扫到了模型文件，且判据源（select:false）在仓内有实际命中', () => {
    expect(files.length).toBeGreaterThanOrEqual(15); // 现状 18+，防目录结构变化导致空转
    const withHidden = files.filter((f) => {
      const src = readModel(f);
      return src !== null && hasHiddenFields(src);
    });
    // 至少 User/Role/UserAvatar 三个（实测），空集说明判据源失效
    expect(withHidden.length).toBeGreaterThanOrEqual(3);
  });

  test('每个带 select:false 的模型：投影 / 白名单出口 / 豁免登记三选一', () => {
    const unaccounted = [];
    for (const file of files) {
      const src = readModel(file);
      if (src === null || !hasHiddenFields(src)) continue;
      const covered =
        hasProjection(src) || hasWhitelistSerializer(src) || EXEMPTIONS[file] !== undefined;
      if (!covered) unaccounted.push(file);
    }
    expect(unaccounted).toEqual([]);
  });

  test('豁免登记表不得腐化：登记的文件必须仍在场、仍带 select:false、且仍未自建出口', () => {
    for (const [file, reason] of Object.entries(EXEMPTIONS)) {
      // 理由必须非空（「写理由」的纪律本身也要被钉）。jest 的 expect 只接一个
      // 参数（第二参数的诊断消息是 vitest 扩展），故消息并入断言对象。
      expect({ file, reasonPresent: String(reason).trim().length > 20 }).toEqual({
        file,
        reasonPresent: true,
      });
      // 只接受纯 basename（拒绝任何路径分隔/跳段），并校验解析结果仍在 MODELS_DIR 内
      expect({
        file,
        isPlainName: /^[A-Za-z0-9_.-]+$/.test(file) && !file.startsWith('.'),
      }).toEqual({
        file,
        isPlainName: true,
      });
      const full = path.resolve(MODELS_DIR, file);
      expect({ file, withinModelsDir: full.startsWith(MODELS_DIR + path.sep) }).toEqual({
        file,
        withinModelsDir: true,
      });
      const src = readModel(file);
      expect({
        file,
        exists: src !== null,
        stillHidden: src !== null && hasHiddenFields(src),
        // 已自建出口的必须从豁免表移除（否则豁免表成为「免检永久席位」）
        notSelfServed: src !== null && !hasProjection(src) && !hasWhitelistSerializer(src),
      }).toEqual({ file, exists: true, stillHidden: true, notSelfServed: true });
    }
  });

  test('反向对照：无出口策略的合成模型必须被判缺（防门禁恒绿）', () => {
    const synthetic = `
      const s = new Schema({ secret: { type: String, select: false } });
      module.exports = mongoose.model('Synthetic', s);
    `;
    const covered =
      hasProjection(synthetic) || hasWhitelistSerializer(synthetic) || EXEMPTIONS['Synthetic.js'];
    expect(covered).toBeFalsy(); // 三种覆盖手段皆未命中 ⇒ 会被 unaccounted 收走
  });
});
