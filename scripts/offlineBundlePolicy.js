/**
 * 离线包判据（scripts/importOfflineBundle.js 的纯逻辑层）
 *
 * 分层理由与 hotUpgradePolicy.js 相同：这里的每一条判据都要能在毫秒级被直接断言
 * （这个包该不该被接受、manifest 与 tarball 是不是同一版），而「执行」
 *（docker load / docker tag）只能靠子进程桩观测。
 *
 * 与在线升级的关系：在线路径的安全模型是「digest 钉扎 + 仓库白名单」——能把镜像引用
 * 指向哪里，就等于能决定线上跑什么代码。离线包绕开了 registry，同一条判据必须换一个
 * 落点重新成立：
 *   · 在线：registry 返回的 manifest 里的 digest 就是真相；
 *   · 离线：包里的 tarball 才是真相，manifest.json 只是「自称」。
 * 因此导入器必须自己算 sha256，再把「load 之后 docker 认为的 RepoDigests」与 manifest
 * 逐字节比对——三者一致才算同一版。
 *
 * 本模块零副作用：不读 process.env、不碰文件系统、不打印、不退出。
 *
 * 每一条判据对应的失败形态（都是「导入报告成功、实际装错」）：
 *   · 只信 manifest.json ⇒ 一个被替换过 payload 的包能装成任意版本，而审计里记的是
 *     manifest 里那个「自称」的 digest；
 *   · 不校验 payload 摘要 ⇒ U 盘拷贝截断/传输损坏被当成完整包装上；
 *   · payload 路径不做约束 ⇒ manifest 写 \`../../etc/...\` 就能把文件写到包外；
 *   · load 之后不核对 RepoDigests ⇒ 包里装的是另一个镜像，脚本却报告成功。
 */

'use strict';

const hotUpgradePolicy = require('./hotUpgradePolicy');

/** 包格式版本。判据只认这一个值：老导入器读新包必须硬失败而不是「尽力而为」 */
const BUNDLE_FORMAT_VERSION = 1;

/** 箱内只允许这两类镜像角色；多一个角色就要多一条「它凭什么被允许」的判据 */
const IMAGE_ROLES = ['app'];

/**
 * 单个 payload 的大小上限（默认 8 GiB）。
 *
 * 存在的理由不是省磁盘：导入器要按 manifest 声明的字节数去读文件，没有上限时
 * 一个畸形 manifest 可以把「校验摘要」这一步变成一次超长磁盘读——磁盘满或读超时
 * 都会表现成「导入卡住」，而不是「这个包不合法」。
 */
const DEFAULT_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024 * 1024;

/** sha256 十六进制（小写）——与 hotUpgradePolicy 的 digest 同口径，不接受大写 */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/** payload 只接受包内相对路径，且必须是 .tar（docker save 的产物） */
const PAYLOAD_FILE_RE = /\.tar$/;

const FLAGS = ['bundle', 'bundle-root', 'allowlist', 'max-payload-bytes', 'apply', 'dry-run', 'help'];

/**
 * 包内相对路径的约束。
 *
 * 拒绝的不是「不好看」，是三种能真正写到包外的形态：
 *   · 绝对路径 / 盘符 / UNC ⇒ 直接指向包外任意位置；
 *   · \`..\` 段 ⇒ 用相对段爬出包根；
 *   · 反斜杠 ⇒ 在 Windows 上被当成目录分隔符，而 \`..\\..\\\` 这类写法在 POSIX 侧
 *     看着只是一个普通文件名，两边判断不一致时必然有一边被骗；
 *   · NUL ⇒ 截断路径，让「校验的那个名字」与「打开的那个名字」不是一回事。
 *
 * @param {string} relPath manifest 里声明的文件路径
 * @returns {string} 规范化后的相对路径
 */
function assertSafeRelativePath(relPath) {
  if (typeof relPath !== 'string' || relPath.trim() === '') {
    throw new Error('包内路径为空：manifest 的 file 必须是非空相对路径');
  }
  const value = relPath.trim();
  if (value.includes('\0')) {
    throw new Error(`包内路径含 NUL 字节：${JSON.stringify(value)}`);
  }
  if (value.includes('\\')) {
    throw new Error(
      `包内路径含反斜杠：${value}\n` +
        '  反斜杠在 Windows 上是目录分隔符，POSIX 上只是普通字符——两边判断不一致时必然有一边被骗。' +
        '包内路径统一用正斜杠。'
    );
  }
  if (value.startsWith('/') || /^[a-zA-Z]:/.test(value)) {
    throw new Error(`包内路径是绝对路径（会写到包外）：${value}`);
  }
  const segments = value.split('/');
  if (segments.some((s) => s === '..')) {
    throw new Error(`包内路径含 \`..\` 段（可爬出包根）：${value}`);
  }
  if (segments.some((s) => s === '' || s === '.')) {
    throw new Error(`包内路径含空段或 \`.\` 段：${value}`);
  }
  return value;
}

/** 正整数校验；manifest 里的 bytes 是「声明值」，导入器据此与实际文件比对 */
function assertPositiveInt(value, what) {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${what} 必须是正整数，收到：${JSON.stringify(value)}`);
  }
  return value;
}

/**
 * 解析并校验 manifest.json。
 *
 * 显式逐字段校验而不是「缺省值兜底」：升级包里每一个缺省值都等于一条被绕过的判据
 *（bytes 缺省⇒不比对大小；sha256 缺省⇒不比对摘要）。缺字段必须报错。
 *
 * @param {unknown} raw JSON.parse 的产物
 * @returns {{ format: number, version: string, buildId: string, createdAt: string, images: Array<object> }}
 */
function parseBundleManifest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('manifest.json 不是对象：离线包根目录里必须先有一份合法的 manifest.json');
  }
  if (raw.format !== BUNDLE_FORMAT_VERSION) {
    throw new Error(
      `不支持的包格式版本：${JSON.stringify(raw.format)}（本导入器只认 ${BUNDLE_FORMAT_VERSION}）\n` +
        '  版本不匹配时必须硬失败：老导入器读新包时「尽力而为」等于丢掉新版本才有的判据。'
    );
  }
  if (typeof raw.version !== 'string' || raw.version.trim() === '') {
    throw new Error('manifest.version 缺失或为空：无法在留痕里记下这次导入的是哪一版');
  }
  const images = raw.images;
  if (!Array.isArray(images) || images.length === 0) {
    throw new Error('manifest.images 必须是非空数组：没有镜像的离线包不是升级包');
  }

  const seenRoles = new Set();
  const seenFiles = new Set();
  const parsed = images.map((entry, i) => {
    const where = `manifest.images[${i}]`;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`${where} 不是对象`);
    }
    if (!IMAGE_ROLES.includes(entry.role)) {
      throw new Error(
        `${where}.role 非法：${JSON.stringify(entry.role)}（只接受 ${IMAGE_ROLES.join(' / ')}）`
      );
    }
    if (seenRoles.has(entry.role)) {
      throw new Error(`${where}.role 重复：${entry.role}（同一个角色只能声明一次）`);
    }
    seenRoles.add(entry.role);

    // 镜像引用继续走在线路径那一条判据：digest 钉扎、拒绝 tag。
    // 离线包不是「tag 的逃生通道」——包内声明的引用同样必须能被审计复核。
    const ref = hotUpgradePolicy.parseImageRef(entry.ref);

    const file = assertSafeRelativePath(entry.file);
    if (!PAYLOAD_FILE_RE.test(file)) {
      throw new Error(`${where}.file 必须是 docker save 产出的 .tar：${file}`);
    }
    if (seenFiles.has(file)) {
      throw new Error(`${where}.file 重复：${file}（同一份 payload 只能被一个角色声明）`);
    }
    seenFiles.add(file);

    const bytes = assertPositiveInt(entry.bytes, `${where}.bytes`);
    const sha256 = entry.sha256;
    if (typeof sha256 !== 'string' || !SHA256_HEX_RE.test(sha256)) {
      throw new Error(
        `${where}.sha256 必须是 64 位小写十六进制，收到：${JSON.stringify(sha256)}\n` +
          '  没有摘要的 payload 等于「不校验的 payload」——损坏的包会被当成完整包装上。'
      );
    }

    return { role: entry.role, ref: ref.ref, repository: ref.repository, digest: ref.digest, file, bytes, sha256 };
  });

  return {
    format: raw.format,
    version: String(raw.version).trim(),
    buildId: typeof raw.buildId === 'string' ? raw.buildId.trim() : '',
    createdAt: typeof raw.createdAt === 'string' ? raw.createdAt.trim() : '',
    images: parsed,
  };
}

/**
 * 实际文件摘要与 manifest 声明是否逐字节一致。
 *
 * 比对前先归一大小写：摘要由外部工具（sha256sum / Get-FileHash）产出，同一份文件在
 * Windows 上常拿到大写。大小写不同不是「摘要不符」，把它们混为一谈会让真正的不符
 * 淹没在噪音里。
 */
function assertDigestEqual(expected, actual, what) {
  const a = String(expected || '')
    .trim()
    .toLowerCase();
  const b = String(actual || '')
    .trim()
    .toLowerCase();
  if (!b) {
    throw new Error(`${what} 的实际摘要为空：无法证明它与 manifest 声明的是同一份文件`);
  }
  if (a !== b) {
    throw new Error(
      `${what} 摘要不符：\n  manifest 声明：${a}\n  实际算出：${b}\n` +
        '  摘要不符通常意味着传输损坏、拷贝截断或 payload 被替换——三种情况都不该继续装。'
    );
  }
  return true;
}

/** 声明字节数与实际字节数一致（截断的 tar 往往摘要也不符，但先报大小更直接指向原因） */
function assertSizeEqual(expected, actual, what) {
  if (Number(expected) !== Number(actual)) {
    throw new Error(
      `${what} 大小不符：manifest 声明 ${expected} 字节，实际 ${actual} 字节\n` +
        '  常见原因是拷贝未完成或磁盘写满——此时按「文件存在」判定成功就会装上一个半截包。'
    );
  }
  return true;
}

/** 超过上限即拒绝，报错里带上限，便于运维判断该调上限还是分包 */
function assertWithinCap(bytes, capBytes, what) {
  if (Number(bytes) > Number(capBytes)) {
    throw new Error(
      `${what} 超过上限：${bytes} > ${capBytes} 字节\n` +
        '  上限用于把「畸形 manifest」挡在读盘之前；确需更大的包请显式调 --max-payload-bytes。'
    );
  }
  return true;
}

/**
 * 包内镜像必须落在离线白名单内。
 *
 * 与在线路径复用同一条前缀判据（hotUpgradePolicy.assertImageAllowed）：
 * 空白名单 = 全拒。离线包同样不是绕开白名单的通道——否则「把包拷到目标机」就等价于
 * 「安装任意代码」，而这个目录的写权限只会随部署方式变化，不能当作唯一边界。
 *
 * @param {{ repository: string }} parsed parseBundleManifest 产出的单条镜像
 * @param {string[]} allowlist 仓库前缀
 */
function assertBundleImageAllowed(parsed, allowlist) {
  return hotUpgradePolicy.assertImageAllowed(parsed, allowlist);
}

/**
 * 解析命令行。
 *
 * 与 hotUpgradePolicy.parseArgs 同口径：未知参数必须报错而不是忽略——\`--bundle-root\`
 * 被静默忽略时，脚本会去默认目录找包，而操作者以为已经指定了别处。
 * 默认演练：不加 --apply 不碰 docker。
 */
function parseArgs(argv = []) {
  const opts = {
    apply: false,
    dryRun: false,
    help: false,
    bundle: '',
    bundleRoot: '',
    allowlist: '',
    maxPayloadBytes: DEFAULT_MAX_PAYLOAD_BYTES,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    if (!raw.startsWith('--')) throw new Error(`无法识别的参数：${raw}`);
    const [name, inlineValue] = raw.slice(2).split('=');
    if (!FLAGS.includes(name)) {
      throw new Error(`未知参数：--${name}（可用：${FLAGS.map((f) => `--${f}`).join(', ')}）`);
    }
    const takeValue = () => {
      if (inlineValue !== undefined) return inlineValue;
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new Error(`--${name} 需要一个值`);
      }
      i += 1;
      return next;
    };
    if (name === 'apply') opts.apply = hotUpgradePolicy.parseBooleanFlag(name, inlineValue);
    else if (name === 'dry-run') opts.dryRun = hotUpgradePolicy.parseBooleanFlag(name, inlineValue);
    else if (name === 'help') opts.help = hotUpgradePolicy.parseBooleanFlag(name, inlineValue);
    else if (name === 'bundle') opts.bundle = takeValue();
    else if (name === 'bundle-root') opts.bundleRoot = takeValue();
    else if (name === 'allowlist') opts.allowlist = takeValue();
    else if (name === 'max-payload-bytes') {
      const n = Number(takeValue());
      if (!Number.isInteger(n) || n <= 0) {
        throw new Error(`--max-payload-bytes 需要正整数，收到：${inlineValue}`);
      }
      opts.maxPayloadBytes = n;
    }
  }
  return opts;
}

/** 把逗号分隔的白名单拆成数组；空串 ⇒ 空数组 ⇒ 后续判据按「全拒」处理 */
function splitAllowlist(value) {
  return String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

module.exports = {
  BUNDLE_FORMAT_VERSION,
  IMAGE_ROLES,
  DEFAULT_MAX_PAYLOAD_BYTES,
  FLAGS,
  assertSafeRelativePath,
  parseBundleManifest,
  assertDigestEqual,
  assertSizeEqual,
  assertWithinCap,
  assertBundleImageAllowed,
  parseArgs,
  splitAllowlist,
};
