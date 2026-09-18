/**
 * 文件权限收紧（跨平台）
 *
 * 背景（M-05）：POSIX 的 chmod 0600/0700 在 Windows/NTFS 上是**空操作**——
 * writeFileSync 的 mode 参数被忽略，chmodSync 只能粗粒度切换只读属性。
 * 于是「生成密钥 → 立刻收紧权限」这条链路在 Windows 上静默失效，
 * 文件继续继承父目录的宽松 ACL（默认 BUILTIN\Users 可读、Authenticated Users 可改），
 * 即**任何本地用户都能读取并改写密钥**。对承载 JWT/AES/HMAC 的目录，
 * 这等于认证与审计完整性的信任根对同机所有账户开放。
 *
 * 本模块把「收紧」从提示升级为**实际执行**：
 *   - POSIX：chmod（目录 0700 / 文件 0600）
 *   - Windows：icacls /inheritance:r /grant:r <user>:F
 *     切断继承、只留当前用户（Administrators 与 SYSTEM 经 UAC 提权本就可取，
 *     无需显式授予；显式授予反而多一条可被滥用的 ACE）
 *
 * 为什么默认执行而非仅提示：调用方（generate-secrets / initData）的**意图**本就是
 * 「创建仅自己可读的密钥载体」。打印一行命令让用户自己跑，等于把安全语义降级为
 * 一句建议——实践中绝大多数人不会执行。此处对齐意图。
 *
 * 失败一律不抛（best-effort）：权限收紧失败不应让密钥生成/服务启动整体失败，
 * 但必须**大声告警**并把可操作命令打出来，绝不静默。
 */

const fs = require('fs');
const { execFileSync } = require('child_process');

const isWindows = process.platform === 'win32';

/**
 * 收紧单个路径的权限
 * @param {string} target 文件或目录的路径
 * @param {{ isDir?: boolean, log?: (msg: string) => void }} [opts]
 * @returns {{ ok: boolean, method: string, detail: string }}
 */
function hardenPath(target, opts = {}) {
  const log = opts.log || (() => {});
  const isDir = opts.isDir !== undefined ? opts.isDir : safeIsDir(target);

  if (!fs.existsSync(target)) {
    return { ok: false, method: 'none', detail: `路径不存在：${target}` };
  }

  if (!isWindows) {
    const mode = isDir ? 0o700 : 0o600;
    try {
      fs.chmodSync(target, mode);
      return { ok: true, method: 'chmod', detail: `已设为 0${mode.toString(8)}` };
    } catch (err) {
      log(`⚠️  chmod 失败（${target}）：${err.message}`);
      return { ok: false, method: 'chmod', detail: err.message };
    }
  }

  // Windows：icacls 切断继承并只留当前用户
  const user = process.env.USERNAME || process.env.USER;
  if (!user) {
    log(`⚠️  无法确定当前用户名，跳过 ACL 收紧：${target}`);
    return { ok: false, method: 'icacls', detail: 'USERNAME 未定义' };
  }

  try {
    const grant = isDir ? `${user}:(OI)(CI)F` : `${user}:F`;
    // 【本轮修复】必须先 /reset 清掉**显式授予**的 ACE，再切断继承并授权。
    //
    // 缺陷实证：`icacls <path> /inheritance:r /grant:r <user>:F` 只移除
    // **继承来的** ACE，不动显式授予的 ACE。若密钥目录曾被显式授予过
    // Everyone / Users（管理员手工改过、或由某个安装器/解压工具带的 ACL），
    // 该 ACE 会在收紧后**存活**——而本函数照旧返回 ok:true，
    // 复核对外的结论就成了「已收紧」：密钥目录实际仍对所有人可读。
    // 这正是本模块最要防的失效形态（假阴性：给用户虚假保证）。
    //
    // /reset 恢复为从父目录继承的默认 ACL（把「显式 ACE」全部清掉，
    // 含 Everyone 这类组账户），随后再 /inheritance:r 切断继承并只授予当前用户。
    // 顺序不可颠倒：先 /inheritance:r 再 /reset 会把切断效果一并重置掉。
    // /T 让目录内既有文件一并重置（否则子文件保留各自的显式 ACE）。
    if (isDir) {
      execFileSync('icacls', [target, '/reset', '/T', '/C', '/Q'], {
        stdio: 'pipe',
        windowsHide: true,
      });
    }
    const args = [target, '/inheritance:r', '/grant:r', grant];
    if (isDir) args.push('/T', '/C', '/Q');
    execFileSync('icacls', args, { stdio: 'pipe', windowsHide: true });
    return { ok: true, method: 'icacls', detail: `已重置显式 ACE 并切断继承，仅授予 ${user}` };
  } catch (err) {
    const hint = `icacls "${target}" /inheritance:r /grant:r "%USERNAME%:${isDir ? '(OI)(CI)F' : 'F'}"`;
    log(`⚠️  ACL 收紧失败（${target}）：${err.message}`);
    log(`    请手动执行：${hint}`);
    return { ok: false, method: 'icacls', detail: err.message };
  }
}

function safeIsDir(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/**
 * 校验权限是否确实收紧（供测试与运维核对）
 *
 * Windows 判定口径：**组账户一律可疑 + 解析空结果 fail-closed**。
 * 之所以不按「只允许当前用户/SYSTEM/Administrators」的白名单判：icacls 输出使用
 * **控制台代码页**编码，非 ASCII 账户名（如中文用户名）会变成替换字符，
 * 无法与预期用户名比对。故反向判断——个人账户不含组名，天然放行；
 * 凡是组名（Users / Everyone / Authenticated Users / sandbox* / SID 形式）皆可疑。
 *
 * 本机实测教训：最初的黑名单只列了 Users / Authenticated Users / Everyone，
 * 结果漏掉了环境实际存在的 CodexSandboxUsers 组 → 未收紧的目录被判为「已收紧」
 * （假阴性）。对权限校验而言假阴性最危险：它让"权限没收紧"看起来像通过了。
 *
 * @returns {{ tightened: boolean, evidence: string }}
 */
function verifyHardened(target) {
  if (!fs.existsSync(target)) return { tightened: false, evidence: '路径不存在' };

  if (!isWindows) {
    const mode = fs.statSync(target).mode & 0o777;
    const want = safeIsDir(target) ? 0o700 : 0o600;
    return {
      tightened: mode === want,
      evidence: `mode=${mode.toString(8)}（期望 ${want.toString(8)}）`,
    };
  }

  let out;
  try {
    out = execFileSync('icacls', [target], { encoding: 'utf8', windowsHide: true });
  } catch (err) {
    return { tightened: false, evidence: `icacls 读取失败：${err.message}` };
  }

  // 抽 ACE 主体：行形如 "<主体>:(I)(OI)(CI)(F)"，首行含路径前缀
  const principals = out
    .split(/\r?\n/)
    .map((line) => line.match(/([^\\\s][^:]*?):(\()/))
    .filter(Boolean)
    .map((m) => m[1].trim().split(/\s+/).pop() || '')
    .filter((n) => n && !/^\uFFFD+$/u.test(n));

  const GROUP_LIKE =
    /(^|\\)(Users|Everyone|Authenticated Users|INTERACTIVE|IUSR|Guests|Administrators|sandbox\w*)$/i;
  const suspicious = principals.filter(
    (name) => GROUP_LIKE.test(name) || /sandbox/i.test(name) || /^S-1-5-32-\d+$/.test(name)
  );

  const evidence =
    principals.length === 0
      ? '未能解析出任何 ACE 主体（icacls 输出异常）'
      : `ACE 主体 ${principals.length} 条，可疑 ${suspicious.length} 条：${principals
          .join(' | ')
          .slice(0, 180)}`;

  // fail-closed：解析不出主体 = 无法确认安全 = 判未收紧
  return { tightened: principals.length > 0 && suspicious.length === 0, evidence };
}

module.exports = { hardenPath, verifyHardened, isWindows };
