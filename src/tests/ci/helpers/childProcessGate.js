/**
 * W3 局部结构契约，不执行被检源码，也不做跨模块污点分析。
 * 仅放行清单中的顶层 const 解构绑定及四个直接调用；其余 child_process 加载
 * （含 node:、ESM、import()、成员访问）一律拒绝。require 的别名/传递/计算访问、
 * module 加载器及非静态模块名不在支持面，fail closed；唯一动态 require 是已钉住
 * readPackageVersion 的本地 package.json 读取。解析失败也必须红，不能退回正则。
 * 签名是排序后的完整函数 AST 的 SHA-256，忽略位置、注释和 Literal 的 raw 拼写，
 * 保留语义（包括 ASI、模板、正则）。变更签名须复核 argv/options 的定义及来源，
 * 不能用测试运行时读取的源码自动生成期望值。反射/eval、依赖内部行为不属此局部闸。
 */
const { createHash } = require('crypto');
const { Linter } = require('eslint');

const APPROVED_BINDING = "const { execFileSync } = require('child_process');";
const CONTRACTS = {
  'src/config/buildInfo.js': {
    binding: APPROVED_BINDING,
    calls: {
      readGitSha: {
        command: 'git',
        count: 1,
        argvTrust:
          "固定 ['rev-parse', '--short=12', 'HEAD']；内联 options，无 shell；cwd 为仓库 ROOT。",
      },
    },
    pins: {
      readGitSha: 'bcb2c931e785fe72c9e2a2a24fa7cb809e206ead02b68902249f348691db86a2',
      // 唯一动态 require 的局部豁免；ROOT 同时是 git cwd 的来源。
      readPackageVersion: '1d54ab1212fa488730947498c49b79bb8c2e464d3bb3daa0175c59b36576479e',
      ROOT: '2b66e0ea0b8c5b9fcb1b34e67c0dcf24e2f00633a8a10a1c07e93e288f18efde',
    },
  },
  'src/utils/filePermission.js': {
    binding: APPROVED_BINDING,
    calls: {
      hardenPath: {
        command: 'icacls',
        count: 2,
        argvTrust:
          'resetArgv/grantArgv/execOpts 均在本函数构造；固定开关、无 shell。target 由内部调用方传入（非本闸证明：现存四处调用方 auditWalPermissions / initData.adminAccount / scripts.generate-secrets / scripts.run-rollback-drill 传的都是内部目录常量，无 req 派生路径），user 来自 currentUsername。',
      },
      verifyHardened: {
        command: 'icacls',
        count: 1,
        argvTrust: '[target] 与内联 options；无 shell。target 的调用方信任不等于固定字面量。',
      },
    },
    pins: {
      hardenPath: '0b7bed3c473e00a989b500a2f6986fa000b22ba5cdf321dda705f7303184a64d',
      verifyHardened: 'a8e5ddbfa039105bd3c9cdfab0f3716e685e87eeec8a48dd216beb26c3e18676',
      // 用户名是环境/OS 账户数据，不可声称固定 argv；连同来源函数一起锁定。
      currentUsername: 'be3092f572df9ed3dbfa22fb584c7a391b666948a634dbfdb9cd276090318886',
    },
  },
};

const OMIT = new Set(['parent', 'loc', 'range', 'start', 'end', 'tokens', 'comments']);
function normalized(value) {
  if (Array.isArray(value)) return value.map(normalized);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .filter((key) => !OMIT.has(key) && !(key === 'raw' && value.type === 'Literal'))
      .map((key) => [key, normalized(value[key])])
  );
}
const signature = (node) =>
  createHash('sha256')
    .update(JSON.stringify(normalized(node)))
    .digest('hex');

/** 独立 Linter 配置，不读取仓库规则；禁用内联 eslint 注释，源码不能关闭此闸。 */
function parse(text) {
  const nodes = [];
  let source;
  const messages = new Linter().verify(
    text,
    [
      {
        languageOptions: {
          ecmaVersion: 'latest',
          sourceType: 'module',
          globals: { require: 'readonly', module: 'readonly' },
        },
        plugins: {
          gate: {
            rules: {
              capture: {
                create(context) {
                  source = context.sourceCode;
                  return { '*': (node) => nodes.push(node) };
                },
              },
            },
          },
        },
        rules: { 'gate/capture': 'error' },
      },
    ],
    { allowInlineConfig: false }
  );
  return { nodes, source, messages };
}
const BINDING_SIGNATURE = signature(parse(APPROVED_BINDING).source.ast.body[0]);
const literalString = (node) =>
  node?.type === 'Literal' && typeof node.value === 'string' ? node.value : null;
const isChildProcess = (name) => name === 'child_process' || name === 'node:child_process';
const isModuleLoader = (name) => name === 'module' || name === 'node:module';
const directCall = (id) =>
  id.parent.type === 'CallExpression' && id.parent.callee === id && !id.parent.optional;
const plainMember = (id, name) =>
  id.parent.type === 'MemberExpression' &&
  id.parent.object === id &&
  !id.parent.computed &&
  !id.parent.optional &&
  id.parent.property.name === name;
function enclosingFunction(node) {
  for (let p = node.parent; p; p = p.parent) {
    if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(p.type))
      return p;
  }
  return null;
}

function pinnedNodes(source, contract, fail) {
  const pins = new Map();
  if (!contract) return pins;
  for (const [name, expected] of Object.entries(contract.pins)) {
    const matches = source.ast.body.flatMap((node) => {
      if (node.type === 'FunctionDeclaration' && node.id.name === name) return [node];
      if (node.type === 'VariableDeclaration')
        return node.declarations.filter((d) => d.id.name === name);
      return [];
    });
    if (matches.length !== 1) {
      fail('pin-missing', source.ast, `局部不变量 ${name} 必须唯一且在顶层`);
      continue;
    }
    const node = matches[0];
    pins.set(name, node);
    const actual = signature(node);
    if (actual !== expected) fail('signature', node, `${name} AST 签名变化：${actual}`);
    // 函数体不变但在外部重新赋值，同样会改变 argv 来源。
    for (const variable of source.getDeclaredVariables(node)) {
      for (const ref of variable.references) {
        if (ref.isWrite() && !ref.init) fail('pin-write', ref.identifier, `${name} 不允许重绑定`);
      }
    }
  }
  return pins;
}

function checkLoaders(state) {
  const { nodes, source, fail, loads } = state;
  const checkSource = (node, specifier) => {
    const name = literalString(specifier);
    if (isChildProcess(name)) loads.push(node);
    else if (name === null || isModuleLoader(name))
      fail('unsupported-loader', node, '非静态模块名/module 加载器未支持');
  };
  for (const node of nodes) {
    if (
      [
        'ImportDeclaration',
        'ImportExpression',
        'ExportNamedDeclaration',
        'ExportAllDeclaration',
      ].includes(node.type) &&
      node.source
    ) {
      checkSource(node, node.source);
    }
    // 这些不是批准的导入入口；计算访问也不得冒充普通 require。
    if (node.type === 'MemberExpression') checkAlternateLoader(node, fail);
  }
  for (const scope of source.scopeManager.scopes) {
    for (const ref of scope.references) {
      const id = ref.identifier;
      if (id.name === 'require') checkRequire(ref, state, checkSource);
      // 只看**解析到全局绑定**的 module：`module` 在本仓是权限/蜜罐的领域字段名
      // （`const { module } = req.query`），按标识符名判会把 5 个业务文件判红。
      // 影子绑定够不到 CJS 的 module 对象 ⇒ createRequire/parent.require 这条旁路本就不存在；
      // 而"自己造一个 module"必须先 `require('node:module')`，那一步 checkSource 已经 fail closed。
      if (
        id.name === 'module' &&
        isGlobalBinding(ref) &&
        !plainMember(id, 'exports') &&
        !isMainComparison(id)
      ) {
        fail('unsupported-loader', id, 'module 的别名/加载器访问未支持');
      }
    }
  }
}

/** 解析不到（未声明）时保守当全局：宁可红也不能漏掉加载器旁路 */
const isGlobalBinding = (ref) =>
  !ref.resolved || (ref.resolved.scope?.type === 'global' && ref.resolved.defs.length === 0);

function isMainComparison(id) {
  const p = id.parent;
  if (p.type !== 'BinaryExpression' || p.operator !== '===') return false;
  const other = p.left === id ? p.right : p.left;
  return (
    other.type === 'MemberExpression' &&
    !other.computed &&
    other.object.name === 'require' &&
    other.property.name === 'main'
  );
}
function checkAlternateLoader(node, fail) {
  const key = node.computed ? literalString(node.property) : node.property.name;
  const root = node.object.name;
  if (
    ['global', 'globalThis'].includes(root) &&
    (key === 'require' || key === 'module' || key === null)
  ) {
    fail('unsupported-loader', node, '全局/计算加载器访问未支持');
  }
  if (
    root === 'process' &&
    ['getBuiltinModule', 'mainModule', 'binding', '_linkedBinding'].includes(key)
  ) {
    fail('unsupported-loader', node, 'process 底层加载器未支持');
  }
}
function checkRequire(ref, state, checkSource) {
  const { pins, fail } = state;
  const id = ref.identifier;
  if (ref.resolved?.defs.length || ref.isWrite()) {
    fail('unsupported-loader', id, 'require 被遮蔽/重绑定');
    return;
  }
  if (directCall(id) && id.parent.arguments.length === 1) {
    const call = id.parent;
    if (
      literalString(call.arguments[0]) === null &&
      enclosingFunction(call) === pins.get('readPackageVersion')
    )
      return;
    checkSource(call, call.arguments[0]);
    return;
  }
  if (
    plainMember(id, 'resolve') &&
    directCall(id.parent) &&
    id.parent.parent.arguments.length === 1
  ) {
    const specifier = literalString(id.parent.parent.arguments[0]);
    if (specifier !== null && !isChildProcess(specifier) && !isModuleLoader(specifier)) return;
  }
  if (plainMember(id, 'main')) {
    const comparison = id.parent.parent;
    const other = comparison.left === id.parent ? comparison.right : comparison.left;
    if (other?.type === 'Identifier' && other.name === 'module' && isMainComparison(other)) return;
  }
  fail('unsupported-loader', id, 'require 的别名、传递或访问形态未支持');
}

function checkBinding(state, contract) {
  const { loads, source, fail } = state;
  if (!contract) {
    for (const load of loads) fail('unregistered-module', load, '未登记模块加载 child_process');
    return null;
  }
  if (loads.length !== 1)
    fail('load-count', source.ast, `必须恰好一次 child_process 加载，实际 ${loads.length}`);
  const load = loads[0];
  const declarator = load?.parent;
  const declaration = declarator?.parent;
  if (
    declarator?.type !== 'VariableDeclarator' ||
    declarator.init !== load ||
    declaration?.parent !== source.ast ||
    signature(declaration) !== BINDING_SIGNATURE
  ) {
    fail(
      'binding',
      load || source.ast,
      "仅批准顶层 const { execFileSync } = require('child_process')"
    );
    return null;
  }
  return source.getDeclaredVariables(declarator)[0];
}

function checkCalls(state, contract, binding) {
  const { pins, calls, fail } = state;
  if (!binding) return;
  for (const ref of binding.references) {
    const id = ref.identifier;
    if (ref.init && id === binding.identifiers[0]) continue;
    if (ref.isWrite() || !directCall(id)) {
      fail('binding-escape', id, 'execFileSync 仅允许直接调用，不得别名、导出、传递或重绑定');
      continue;
    }
    const call = id.parent;
    const fn = enclosingFunction(call);
    const entry = Object.entries(contract.calls).find(([name]) => pins.get(name) === fn);
    if (
      !entry ||
      literalString(call.arguments[0]) !== entry[1].command ||
      call.arguments.length !== 3
    ) {
      fail('unknown-call', call, '未批准的函数/命令/调用形态');
      continue;
    }
    calls.push({ function: entry[0], command: entry[1].command });
  }
  for (const [name, spec] of Object.entries(contract.calls)) {
    const actual = calls.filter((call) => call.function === name).length;
    if (actual !== spec.count)
      fail(
        'call-count',
        pins.get(name) || state.source.ast,
        `${name} 调用数 ${actual}，应为 ${spec.count}`
      );
  }
}

function checkChildProcess(rel, text) {
  const parsed = parse(text);
  const violations = [];
  const calls = [];
  const fail = (code, node, message) =>
    violations.push({ code, line: node.loc.start.line, message });
  if (parsed.messages.length || !parsed.source) {
    return {
      violations: [{ code: 'parse', message: parsed.messages.map((m) => m.message).join('; ') }],
      calls,
      loads: 0,
    };
  }
  const contract = Object.hasOwn(CONTRACTS, rel) ? CONTRACTS[rel] : null;
  const pins = pinnedNodes(parsed.source, contract, fail);
  const state = { ...parsed, pins, fail, loads: [], calls };
  checkLoaders(state);
  const binding = checkBinding(state, contract);
  checkCalls(state, contract, binding);
  return { violations, calls, loads: state.loads.length };
}

module.exports = { checkChildProcess, CONTRACTS };
