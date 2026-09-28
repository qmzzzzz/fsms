/**
 * 数据库口令 → 连接串 这条链的「驱动真的收得下」契约
 *
 * 断裂点（真实存在过，不是假想）：`docker-compose.yml` 头注释里的手抄版用
 * `openssl rand -base64 32` 生成 `mongo_root_password`，再用
 * `printf 'mongodb://%s:%s@...'` 把它直接拼进 userinfo 段。base64 字符集含 `/`
 * （32 字节输出约一半概率出现），而驱动对未转义的 `/` `:` `#` `?` 在发起网络之前
 * 就抛 `MongoParseError: Password contains unescaped characters` ⇒ 应用启动即退出。
 * `scripts/generate-secrets.js` 走的是 `encodeURIComponent` 那条路，所以它没错——
 * 错的是「两条路径看起来等价、实际不等价」，而运维正是在两者之间手抄混用。
 *
 * 为什么在 `mongoose.connect` 上验证而不是 `new MongoClient()`：应用真正的消费点是
 * 前者（`src/config/database.js` 记录了 mongoose 与顶层 mongodb 内嵌着两份不同版本的
 * 连接串解析器、行为并不一致）。语法非法时驱动在联网**之前**就抛错，因此
 * 「没有 MongoParseError」就等价于「这条串语法合法」，不需要真连上一个 MongoDB
 * （主机写死成永不可达的 127.0.0.1:9，探针超时 15ms）。
 *
 * 每条断言的假绿防线：
 *   - 先自证探针：已知非法的字符必须被判非法、percent-encode 后必须被判合法，
 *     否则「整串都合法」可以靠一个恒说合法的探针变绿。
 *   - 手抄版按**整个字符集**逐字符过驱动（hex 16 个 / base64 64 个），不是抽一个样例。
 *   - 组合方式与字符集互相约束：无转义的组合命令 ⇒ 它引用的每个密钥都必须在原始安全集内。
 *   - 生成器：跑真脚本、读真产物、userinfo 按字节比对，并与手抄版模板交叉对账
 *     （主机/端口/库名/选项/口令熵任一侧漂移都会红）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const mongoose = require('mongoose');

const repoRoot = path.join(__dirname, '..', '..', '..');
const COMPOSE_FILE = path.join(repoRoot, 'docker-compose.yml');
const GENERATOR_FILE = path.join(repoRoot, 'scripts', 'generate-secrets.js');

const DEAD_HOST = '127.0.0.1:9';
const CONNECT_OPTS = { serverSelectionTimeoutMS: 15, connectTimeoutMS: 15, directConnection: true };

/** 口令段里未转义即被驱动拒绝的字符（实测于 mongoose 8.24.1 的消费点） */
const FATAL_IN_PASSWORD = ['/', ':', '#', '?', '%'];

/** openssl 编码 → 该编码可能产出的**全部**字符（全字符集，不是抽样） */
const ALPHABETS = {
  hex: '0123456789abcdef',
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
};

/**
 * 以消费点判定一条 URI 的语法。
 * @returns {Promise<{parseError: boolean, kind: string}>}
 */
async function probeUri(uri) {
  try {
    await mongoose.connect(uri, CONNECT_OPTS);
    return { parseError: false, kind: 'RESOLVED' };
  } catch (error) {
    return {
      parseError: error.constructor.name === 'MongoParseError',
      kind: error.constructor.name,
    };
  } finally {
    await mongoose.disconnect().catch(() => {});
  }
}

const isRejectedByParser = async (uri) => (await probeUri(uri)).parseError;

// ================= compose 头注释里「手抄版」的解析 =================

/** 剥掉 `# ` 前缀，并把以 `\` 续行的物理行合成逻辑行（printf 那条命令跨 3 行） */
function commentedRecipeLines(text) {
  const logical = [];
  let pending = '';
  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (!trimmed.startsWith('#')) continue;
    const body = trimmed.replace(/^#+/, '').trim();
    if (!body) continue;
    const joined = pending ? `${pending} ${body}` : body;
    if (joined.endsWith('\\')) {
      pending = joined.slice(0, -1).trim();
    } else {
      logical.push(joined);
      pending = '';
    }
  }
  if (pending) logical.push(pending);
  return logical;
}

const findRecipe = (lines, secretName) =>
  lines.find((line) => new RegExp(`>\\s*\\.?/?secrets/${secretName}(\\b|$)`).test(line));

/** 从 `openssl rand -hex 32` 取编码与字节数；不是 openssl 命令则返回 null */
function parseOpensslRecipe(line) {
  const m = line ? /openssl rand -(hex|base64)\s+(\d+)/.exec(line) : null;
  return m ? { encoding: m[1], bytes: Number(m[2]) } : null;
}

/** 该密钥可能出现的字符集：openssl 配方取其编码全集，字面量配方取字面量本身 */
function charsetOfRecipe(lines, secretName) {
  const line = findRecipe(lines, secretName);
  if (typeof line !== 'string') return null;
  const openssl = parseOpensslRecipe(line);
  if (openssl) return ALPHABETS[openssl.encoding] ?? null;
  const literal = /'([^']*)'/.exec(line);
  return literal ? literal[1] : null;
}

/** printf 模板 → 真正的 URI（模板必须恰有两个 %s，依次填用户名、口令） */
function composeTemplate(template, user, password) {
  const parts = template.split('%s');
  if (parts.length !== 3) throw new Error(`组合模板的 %s 占位符不是 2 个：${template}`);
  return `${parts[0]}${user}${parts[1]}${password}${parts[2]}`;
}

const uriTemplateOf = (lines) =>
  (/printf '(mongodb:\/\/[^']+)'/.exec(findRecipe(lines, 'mongodb_uri') || '') || [])[1] ?? null;

// ================= generate-secrets.js 的源码形状 =================

/** 取 `secrets.mongodb_uri = ...` 这条赋值语句的源码文本 */
function generatorUriAssignment(source) {
  const start = source.indexOf('secrets.mongodb_uri =');
  if (start < 0) throw new Error('generate-secrets.js 里找不到 secrets.mongodb_uri 赋值');
  const end = source.indexOf(';', start);
  return source.slice(start, end < 0 ? source.length : end);
}

async function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zzb-uri-'));
  try {
    return await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('驱动语法前提自证（防止字符集探针假绿）', () => {
  test('口令里未转义的 / : # ? % 确实被拒绝', async () => {
    const rejected = [];
    for (const c of FATAL_IN_PASSWORD) {
      if (await isRejectedByParser(`mongodb://u:x${c}x@${DEAD_HOST}/fsms`)) rejected.push(c);
    }
    expect({ rejected }).toEqual({ rejected: FATAL_IN_PASSWORD });
  });

  test('同一批字符 percent-encode 后确实被接受（探针不是一律判非法）', async () => {
    const accepted = [];
    for (const enc of ['%2F', '%3A', '%23', '%3F', '%25']) {
      if (!(await isRejectedByParser(`mongodb://u:x${enc}x@${DEAD_HOST}/fsms`))) accepted.push(enc);
    }
    expect({ accepted }).toEqual({ accepted: ['%2F', '%3A', '%23', '%3F', '%25'] });
  });

  test('探针确实停在语法层：无凭据的普通串只报网络错', async () => {
    const verdict = await probeUri(`mongodb://${DEAD_HOST}/fsms`);
    expect(verdict).toEqual({ parseError: false, kind: 'MongooseServerSelectionError' });
  });
});

describe('docker-compose 手抄版：字符集与组合方式必须自洽', () => {
  const lines = commentedRecipeLines(fs.readFileSync(COMPOSE_FILE, 'utf8'));

  test('三条配方都解析得到（解析锚点失效要红，不能变成"没有配方所以全通过"）', () => {
    const password = findRecipe(lines, 'mongo_root_password');
    const username = findRecipe(lines, 'mongo_root_username');
    const uri = findRecipe(lines, 'mongodb_uri');
    expect(typeof password).toBe('string');
    expect(typeof username).toBe('string');
    expect(typeof uri).toBe('string');
    expect(parseOpensslRecipe(password)).toBeTruthy();
    expect(uriTemplateOf(lines)).toBeTruthy();
  });

  test('mongo_root_password 的整个字符集逐字符被驱动原始接受', async () => {
    const recipe = parseOpensslRecipe(findRecipe(lines, 'mongo_root_password'));
    expect(recipe).toBeTruthy();
    const charset = ALPHABETS[recipe.encoding];
    expect(typeof charset).toBe('string');

    const offenders = [];
    for (const c of charset) {
      if (await isRejectedByParser(`mongodb://u:${c}@${DEAD_HOST}/fsms`)) offenders.push(c);
    }
    expect({ encoding: recipe.encoding, offenders }).toEqual({
      encoding: recipe.encoding,
      offenders: [],
    });
  });

  test('组合命令不含转义 ⇒ 两个 %s 位置上可能出现的每个字符都被原始接受', async () => {
    const uriLine = findRecipe(lines, 'mongodb_uri');
    const operands = [...uriLine.matchAll(/\$\(\s*cat\s+\.?\/?secrets\/([a-z_]+)\s*\)/g)].map(
      (m) => m[1]
    );
    if (/encodeURIComponent|urlencode|jq .*@uri/.test(uriLine)) {
      // 另一种自洽写法：字符集不限，但组合时转义——仍要求它读的就是这两个密钥文件
      expect(operands).toEqual(['mongo_root_username', 'mongo_root_password']);
      return;
    }
    const template = uriTemplateOf(lines);
    expect(template).toBeTruthy();
    expect(operands).toEqual(['mongo_root_username', 'mongo_root_password']);

    const userChars = charsetOfRecipe(lines, 'mongo_root_username');
    const passChars = charsetOfRecipe(lines, 'mongo_root_password');
    expect(typeof userChars).toBe('string');
    expect(typeof passChars).toBe('string');

    const sampleUser = userChars.length <= 32 ? userChars : 'u0';
    const samplePass = passChars.length <= 32 ? passChars : 'p0';
    const offenders = [];
    for (const c of passChars) {
      if (await isRejectedByParser(composeTemplate(template, sampleUser, c))) {
        offenders.push(`password:${c}`);
      }
    }
    for (const c of userChars) {
      if (await isRejectedByParser(composeTemplate(template, c, samplePass))) {
        offenders.push(`username:${c}`);
      }
    }
    expect({ offenders }).toEqual({ offenders: [] });
  });

  test('手抄版与生成器的 URI 骨架逐项一致（主机/端口/库名/authSource 不许各走一侧）', () => {
    const template = uriTemplateOf(lines);
    expect(template).toBeTruthy();
    const withoutPlaceholders = template.replace(/%s/g, '');
    expect(withoutPlaceholders.startsWith('mongodb://:')).toBe(true);
    const handTail = withoutPlaceholders.slice(withoutPlaceholders.indexOf('@'));
    const generatorTail =
      /'(@[^']*fire_safety_db[^']*)'/.exec(fs.readFileSync(GENERATOR_FILE, 'utf8')) || [];
    expect(generatorTail[1]).toBeTruthy();
    expect(handTail).toBe(generatorTail[1]);
  });

  test('两条路径的口令熵一致（换编码可以，缩水不行）', () => {
    const hand = parseOpensslRecipe(findRecipe(lines, 'mongo_root_password'));
    const generator =
      /mongo_root_password:\s*(b64|hex)\((\d+)\)/.exec(fs.readFileSync(GENERATOR_FILE, 'utf8')) ||
      [];
    expect(hand).toBeTruthy();
    expect(generator[2]).toBeTruthy();
    expect(hand.bytes).toBe(Number(generator[2]));
    expect(hand.bytes).toBeGreaterThanOrEqual(16);
  });
});

describe('scripts/generate-secrets.js 真实产物', () => {
  test('生成的 mongodb_uri 被驱动接受，且 userinfo 逐字节等于口令文件', async () => {
    await withTempDir(async (dir) => {
      execFileSync(process.execPath, [GENERATOR_FILE, '--out', dir], {
        encoding: 'utf8',
        cwd: repoRoot,
      });
      const passwordFile = fs.readFileSync(path.join(dir, 'mongo_root_password'), 'utf8');
      const usernameFile = fs.readFileSync(path.join(dir, 'mongo_root_username'), 'utf8');
      const uri = fs.readFileSync(path.join(dir, 'mongodb_uri'), 'utf8');

      expect(await probeUri(uri)).toEqual({
        parseError: false,
        kind: 'MongooseServerSelectionError',
      });

      const body = uri.slice('mongodb://'.length);
      const [rawUser, ...rawPass] = body.slice(0, body.lastIndexOf('@')).split(':');
      expect({
        user: decodeURIComponent(rawUser),
        pass: decodeURIComponent(rawPass.join(':')),
      }).toEqual({ user: usernameFile, pass: passwordFile });
      // 口令确实是 base64 形态——否则上面那次 decode 只是恒等变换的巧合，
      // "转义是承重的"这条结论就没了落脚点（承重由差分用例实测）
      expect(passwordFile).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    });
  });

  test('赋值语句对用户名与口令各做一次 encodeURIComponent（去掉转义会被抓到）', () => {
    const assignment = generatorUriAssignment(fs.readFileSync(GENERATOR_FILE, 'utf8'));
    const calls = [...assignment.matchAll(/encodeURIComponent\((secrets\.[a-z_]+)\)/g)].map(
      (m) => m[1]
    );
    expect(calls).toEqual(['secrets.mongo_root_username', 'secrets.mongo_root_password']);
    expect(assignment.replace(/encodeURIComponent\([^)]*\)/g, '')).not.toMatch(
      /secrets\.mongo_root/
    );
  });
});

describe('两条路径不可混用（差分实测）', () => {
  test('含 / 的 base64 口令：手抄模板直接拼必炸，加转义即可——转义是承重的', async () => {
    const template = uriTemplateOf(commentedRecipeLines(fs.readFileSync(COMPOSE_FILE, 'utf8')));
    expect(template).toBeTruthy();
    // 一个可解码、且**编码文本**里确实含 '/' 的 base64 口令。这条自证不能省：
    // 'YWJjLzEyMw==' 看着像"含斜杠"，斜杠其实在解码后的字节里，用它做差分样本会假绿。
    const password = Buffer.from([0x59, 0x57, 0x4a, 0x6a, 0xff, 0xff, 0xff]).toString('base64');
    expect({
      base64Charset: /^[A-Za-z0-9+/]+={0,2}$/.test(password),
      containsSlash: password.includes('/'),
    }).toEqual({ base64Charset: true, containsSlash: true });

    const rawRejected = await isRejectedByParser(composeTemplate(template, 'firesafety', password));
    expect({ rawRejected }).toEqual({ rawRejected: true });

    const escaped = composeTemplate(
      template,
      encodeURIComponent('firesafety'),
      encodeURIComponent(password)
    );
    expect(await probeUri(escaped)).toEqual({
      parseError: false,
      kind: 'MongooseServerSelectionError',
    });
  });
});
