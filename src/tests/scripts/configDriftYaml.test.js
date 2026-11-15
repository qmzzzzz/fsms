'use strict';

const fs = require('fs');
const path = require('path');
const yamlLite = require('../../../scripts/configDriftYaml');

const ROOT = path.resolve(__dirname, '..', '..', '..');

describe('configDriftYaml.parse：标量类型与 js-yaml core 口径一致', () => {
  test('布尔 / 整数 / 浮点 / null / 字符串 / 引号标量', () => {
    const doc = yamlLite.parse(
      [
        'a: true',
        'b: false',
        'c: 5',
        'd: 1.5',
        'e:',
        'f: hello',
        "g: '0:0'",
        'h: "x\\ty"',
        'i: 10s',
        'j: 1g',
      ].join('\n')
    );
    expect(doc).toEqual({
      a: true,
      b: false,
      c: 5,
      d: 1.5,
      e: null,
      f: 'hello',
      g: '0:0',
      h: 'x\ty',
      i: '10s',
      j: '1g',
    });
  });

  test('值里的冒号不切分键（mongo digest 形态）', () => {
    const doc = yamlLite.parse('image: mongo:8.0.34@sha256:4a4a\n');
    expect(doc.image).toBe('mongo:8.0.34@sha256:4a4a');
  });

  test('变量插值与中文默认值原样保留为字符串', () => {
    const doc = yamlLite.parse('X: ${TRUSTED_PROXY_CIDRS:?必须显式配置（如 172.28.0.0/16）}\n');
    expect(doc.X).toBe('${TRUSTED_PROXY_CIDRS:?必须显式配置（如 172.28.0.0/16）}');
  });
});

describe('configDriftYaml.parse：结构形态', () => {
  test('嵌套映射 + 块序列 + 注释行跳过', () => {
    const doc = yamlLite.parse(
      [
        'services:',
        '  # 顶层注释',
        '  app:',
        '    read_only: true',
        '    cap_drop:',
        '      - ALL',
        '    cap_add:',
        '      - CHOWN',
        '      - DAC_OVERRIDE',
      ].join('\n')
    );
    expect(doc.services.app).toEqual({
      read_only: true,
      cap_drop: ['ALL'],
      cap_add: ['CHOWN', 'DAC_OVERRIDE'],
    });
  });

  test('跨行流式序列（redis healthcheck 的 test 形态）与引号内竖线', () => {
    const doc = yamlLite.parse(
      [
        'healthcheck:',
        '  test:',
        '    [',
        "      'CMD-SHELL',",
        "      'redis-cli ping | grep -q PONG',",
        '    ]',
        '  retries: 5',
      ].join('\n')
    );
    expect(doc.healthcheck.test).toEqual(['CMD-SHELL', 'redis-cli ping | grep -q PONG']);
    expect(doc.healthcheck.retries).toBe(5);
  });

  test('块标量：| 保留换行（含空行），>- 折叠为单行且无尾随换行', () => {
    const doc = yamlLite.parse(
      [
        'entrypoint:',
        '  - sh',
        '  - |',
        '    line1',
        '',
        '    line3',
        'healthcheck:',
        '  test:',
        '    - CMD-SHELL',
        '    - >-',
        '      fold a',
        '      fold b',
      ].join('\n')
    );
    expect(doc.entrypoint).toEqual(['sh', 'line1\n\nline3\n']);
    expect(doc.healthcheck.test).toEqual(['CMD-SHELL', 'fold a fold b']);
  });

  test('值后行内注释被剥掉，且引号内的 # 不是注释', () => {
    const doc = yamlLite.parse(['a: value # 注释', "b: 'x # y'", 'c: 1'].join('\n'));
    expect(doc).toEqual({ a: 'value', b: 'x # y', c: 1 });
  });

  test('空值：下一行同缩进 ⇒ null（!override 剥离后的形态）', () => {
    const doc = yamlLite.parse(['privileged:', 'networks:', '  - data'].join('\n'));
    expect(doc).toEqual({ privileged: null, networks: ['data'] });
  });

  test('值位置的 !tag 被剥掉（!override 后跟块内容）', () => {
    const doc = yamlLite.parse(['ports: !override', "  - '127.0.0.1:3001:3000'"].join('\n'));
    expect(doc.ports).toEqual(['127.0.0.1:3001:3000']);
  });
});

describe('configDriftYaml.parse：fail-closed（解析不了就抛）', () => {
  test('序列内映射项（- key: value）暂不支持 ⇒ 抛错而不是给错账面', () => {
    expect(() => yamlLite.parse('items:\n  - name: x\n')).toThrow(/序列内映射项/);
  });

  test('流式集合未闭合 ⇒ 抛错', () => {
    expect(() => yamlLite.parse('a: [1, 2\nb: 3\n')).toThrow(/未闭合/);
  });

  test('意外的更深缩进 ⇒ 抛错', () => {
    expect(() => yamlLite.parse('a: 1\n    b: 2\n')).toThrow(/缩进/);
  });
});

describe('configDriftYaml.parse：真实 docker-compose.yml 抽样对账', () => {
  const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
  const doc = yamlLite.parse(compose);

  test('服务面形状：app 只读、能力最小化、memory 上限与基线口径一致', () => {
    expect(doc.services.app.read_only).toBe(true);
    expect(doc.services.app.user).toBe('0:0');
    expect(doc.services.app.cap_drop).toEqual(['ALL']);
    expect(doc.services.app.deploy.resources.limits.memory).toBe('1g');
    expect(doc.services.mongo.deploy.resources.limits.memory).toBe('2g');
  });

  test('mongo healthcheck 的块标量被折叠为与 js-yaml 相同的字符串', () => {
    const test = doc.services.mongo.healthcheck.test;
    expect(test[0]).toBe('CMD-SHELL');
    expect(test[1]).not.toMatch(/\n/);
    expect(test[1]).toContain('db.getSiblingDB("admin").auth(u, p)');
    expect(doc.services.mongo.healthcheck.retries).toBe(5);
  });

  test('redis healthcheck 的跨行流式序列与 user 标量', () => {
    expect(doc.services.redis.user).toBe('redis');
    expect(doc.services.redis.healthcheck.test[0]).toBe('CMD-SHELL');
    expect(doc.services.redis.healthcheck.test[1]).toContain('grep -q PONG');
  });
});

describe('供应链：config-drift-check.js 不再依赖传递依赖 js-yaml', () => {
  test('脚本不再 require js-yaml，改用仓内 configDriftYaml', () => {
    const src = fs.readFileSync(path.join(ROOT, 'scripts/config-drift-check.js'), 'utf8');
    expect(src.includes("require('js-yaml')")).toBe(false);
    expect(src).toContain("require('./configDriftYaml')");
  });
});
