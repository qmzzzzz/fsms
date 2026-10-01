/**
 * 基础镜像 digest 钉版门禁——真实仓库文件（finding #7：镜像钉版是门禁假象）
 *
 * 背景：仓库里原本唯一的 digest 覆盖是 src/tests/imageDigestGate.test.js，它验证
 * scripts/capture-image-digests.sh 在 tmpdir 夹具上的行为；对真实 Dockerfile /
 * docker-compose.yml 没有任何断言。于是「脚本行为正确」与「脚本真的跑过且
 * --apply 过」是两回事：真实文件可以带着可变 tag 一直提交，门禁全程绿灯——
 * 这就是门禁假象。
 *
 * 本文件把真实文件的钉版状态钉成门禁：
 *   1. Dockerfile 每个 FROM 指令都必须是 `name:tag@sha256:<64 位 hex>` 形态
 *      （先自证解析到恰好 3 个 FROM，防止解析器退化后断言空转出假绿）；
 *   2. 三个 FROM 的 digest 必须完全一致——builder/web-builder/runtime 的工具链
 *      漂移不变量：libc/OpenSSL 版本不同，原生模块要到运行时才暴露不兼容；
 *   3. docker-compose.yml 的 redis image 指令行必须带 @sha256（注释行不算数）；
 *   4. Dockerfile 三处 FROM 的 digest 必须等于下方 PINNED_NODE_DIGEST 字面量。
 *
 * 【第 4 条为什么是字面量】digest 是**外部落的事实**，不是可复算逻辑：它来自
 * 2026-10-01 对 registry 的双源核验——docker.m.daocloud.io（Docker Hub 的
 * pull-through 镜像）与 AWS ECR Public 的 docker/library/node 各自按 tag
 * 22.14.0-alpine 取到的 manifest 字节逐字节一致，且本地对返回字节自算的 sha256
 * 与 Docker-Content-Digest 相等（内容寻址自证；当日 Docker Hub 官方 tag API 在
 * 本网络不可达：DNS 污染）。任何代码都无法从仓库内重新推导出这个值，所以只能
 * 以字面量 + 来源注释的方式钉进门禁。升级基础镜像时的正确路径：在部署机跑
 * scripts/capture-image-digests.sh 重新捕获 → 同一次改动里同步更新 Dockerfile
 * 三处 FROM 与本文件字面量（漏任何一边都会红灯，这是刻意的）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const DOCKERFILE = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');
const COMPOSE = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');

// 2026-10-01 双源核验（来源与核验方式见文件头）。node:22.14.0-alpine 的
// manifest list digest（多架构 OCI image index，含 linux/amd64 与 linux/arm64）。
const PINNED_NODE_DIGEST = '9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944';
const PINNED_NODE_REF = `node:22.14.0-alpine@sha256:${PINNED_NODE_DIGEST}`;

/** 解析 Dockerfile 的 FROM 指令行：跳过注释行，容忍前导空白 */
function fromLines(content) {
  return content
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith('#'))
    .filter((line) => /^\s*FROM\b/.test(line));
}

/** 从单条 FROM 行解析 {image, stage}；image 应为 `name:tag@sha256:hex` 形态 */
function parseFrom(line) {
  const m = line.trim().match(/^FROM\s+(\S+)(?:\s+AS\s+(\S+))?$/i);
  expect(m).toBeTruthy();
  return { image: m[1], stage: m[2] || null };
}

describe('基础镜像 digest 钉版门禁（真实 Dockerfile / docker-compose.yml）', () => {
  test('解析器自证：真实 Dockerfile 恰好 3 个 FROM，阶段名符合预期（防假绿地基）', () => {
    const stages = fromLines(DOCKERFILE).map(parseFrom);
    // 若格式漂移导致解析到 0 个 FROM，后面所有「每个 FROM 都带 digest」的断言
    // 都会空转通过——所以先把解析本身钉死：数量与阶段名一个都不能漂。
    expect(stages).toHaveLength(3);
    expect(stages.filter((s) => s.stage === 'builder')).toHaveLength(1);
    expect(stages.filter((s) => s.stage === 'web-builder')).toHaveLength(1);
    expect(stages.filter((s) => s.stage === null)).toHaveLength(1); // runtime 无 AS
  });

  test('每个 FROM 都钉了 @sha256:<64 位 hex>，且就是核验过的 node 镜像引用', () => {
    const stages = fromLines(DOCKERFILE).map(parseFrom);
    expect(stages.length).toBeGreaterThan(0);
    for (const { image } of stages) {
      expect(image).toMatch(/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/);
      expect(image).toBe(PINNED_NODE_REF);
    }
  });

  test('三个 FROM 的 digest 完全一致（builder/web-builder/runtime 工具链漂移不变量）', () => {
    const digests = fromLines(DOCKERFILE).map((line) => {
      const m = line.match(/@sha256:([0-9a-f]{64})/);
      expect(m).toBeTruthy();
      return m[1];
    });
    expect(new Set(digests).size).toBe(1);
    expect(digests[0]).toBe(PINNED_NODE_DIGEST);
  });

  test('docker-compose.yml 的 redis image 指令行带 @sha256（注释行不算数）', () => {
    // 行锚定：compose 注释里也有一份 `docker pull redis:7-alpine@sha256:...`
    // 示例文本，不带 `image:` 锚的断言会被注释假通过。
    const imageLines = COMPOSE.split(/\r?\n/).filter((line) =>
      /^\s*image:\s*redis:\S*@sha256:[0-9a-f]{64}\s*$/.test(line)
    );
    expect(imageLines).toHaveLength(1);
    expect(imageLines[0].trim()).toMatch(/^image:\s+redis:7-alpine@sha256:[0-9a-f]{64}$/);
  });
});
