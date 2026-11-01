/**
 * app 容器的文件型 secret 权限适配契约（2026-10-24）
 *
 * 缺陷本体：compose 的 `secrets: file:` 在 Linux 上是 bind mount，容器内保留
 * 宿主文件的属主/权限（Compose issue #9648）。`generate-secrets.js` 刻意把密钥
 * 写成 0600、目录 0700，属主是部署用户；而镜像里的应用用户是 UID 1001
 * （nodejs）。UID 1001 既不是属主也不在属组，读 `/run/secrets/*` 直接 EACCES，
 * 服务在 `config/secrets.js` 的 readFileSync 处启动失败。
 *
 * 本文件锁的是「修复链」而不是某一行文本：
 *   1. 镜像入口脚本必须在 root 阶段把 /run/secrets 复制到 tmpfs，收紧到 0400，
 *      chown 给 nodejs，再把 `*_FILE` 指针重写到副本路径；
 *   2. 复制完成后必须 su-exec 降权，应用与 dumb-init 都是 nodejs；
 *   3. compose 只补入口脚本真正需要的最小能力集，且保留只读根文件系统；
 *   4. 回归方向：删掉 user/cap_add/tmpfs、把 chown 提到 chmod 之前、或把
 *      宿主机权限改成 0644（at-rest 降级）都必须被本文件拒绝。
 *
 * 边界：静态断言，不跑真实 docker。真实权限行为由 `docker compose up` 与
 * deployment/rollback-drill.md 覆盖；本文件保证的是「代码里的修复链没有断」。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const dockerfile = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');
const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
const entrypoint = fs.readFileSync(path.join(ROOT, 'docker/app-entrypoint.sh'), 'utf8');
/** 去掉整行注释：注释里会写 0700/0644 这类对照文本，不能参与"禁止"判定 */
const entrypointCode = entrypoint
  .split(/\r?\n/)
  .filter((l) => !/^\s*#/.test(l))
  .join('\n');

/** 顶层服务块（按 2 空格缩进的 key 切分；嵌套 key 是 4 空格起，不会误切） */
function serviceBlockFrom(text, name) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => new RegExp(`^ {2}${name}:\\s*$`).test(l));
  if (start < 0) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {2}[A-Za-z0-9_.-]+:\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

/** 取服务块里某个 4 空格子键的 6 空格列表项 */
function listItems(block, key) {
  const lines = block.split(/\r?\n/);
  const at = lines.findIndex((l) => new RegExp(`^ {4}${key}:\\s*$`).test(l));
  if (at < 0) return [];
  const out = [];
  for (let i = at + 1; i < lines.length; i += 1) {
    const m = /^ {6}-\s*(\S+)\s*$/.exec(lines[i]);
    if (!m) break;
    out.push(m[1].replace(/^['"]|['"]$/g, ''));
  }
  return out;
}

const appBlock = serviceBlockFrom(compose, 'app');

describe('app 入口脚本：复制 → 收紧 → 改属主 → 降权', () => {
  test('前提自证：切到了 app 块，且脚本/镜像/编排三份文件都非空', () => {
    expect(appBlock).not.toBeNull();
    expect(appBlock).toMatch(/^ {4}image:\s+\$\{APP_IMAGE/m);
    expect(dockerfile.length).toBeGreaterThan(0);
    expect(entrypoint.length).toBeGreaterThan(0);
  });

  test('脚本是 POSIX sh、fail-closed，且不含 CR（CRLF 会让容器里的 sh 解析失败）', () => {
    expect(entrypoint.startsWith('#!/bin/sh\n')).toBe(true);
    expect(entrypoint).toMatch(/^set -eu$/m);
    expect(entrypoint).not.toMatch(/\r/);
  });

  test('复制源/目标与权限：/run/secrets → /run/app-secrets，文件 0400、目录 0500', () => {
    expect(entrypoint).toMatch(/^SECRET_SRC=\/run\/secrets$/m);
    expect(entrypoint).toMatch(/^SECRET_DST=\/run\/app-secrets$/m);
    expect(entrypoint).toMatch(/cp "\$src" "\$SECRET_DST\/\$name"/);
    expect(entrypoint).toMatch(/chmod 0400 "\$SECRET_DST\/\$name"/);
    expect(entrypoint).toMatch(/chown nodejs:nodejs "\$SECRET_DST\/\$name"/);
    expect(entrypoint).toMatch(/chmod 0500 "\$SECRET_DST"/);
    expect(entrypoint).toMatch(/chown nodejs:nodejs "\$SECRET_DST"/);
    // 反向：密钥模式不得对 group/other 开放读权限（末位 4-7）
    expect(entrypointCode).not.toMatch(/chmod\s+0?[0-7]{2}[4-7]\b/);
  });

  test('chmod 必须排在 chown 之前：倒过来在最小 capability 集下会缺 FOWNER', () => {
    const chmodAt = entrypoint.indexOf('chmod 0400 "$SECRET_DST/$name"');
    const chownAt = entrypoint.indexOf('chown nodejs:nodejs "$SECRET_DST/$name"');
    expect(chmodAt).toBeGreaterThan(-1);
    expect(chownAt).toBeGreaterThan(-1);
    expect(chmodAt).toBeLessThan(chownAt);
  });

  test('把 *_FILE 指针重写到副本路径（compose 文本仍保持 /run/secrets 挂载点）', () => {
    expect(entrypoint).toMatch(/rewrite_file_pointers\(\)/);
    expect(entrypoint).toMatch(/\*_FILE=\/run\/secrets\/\*/);
    expect(entrypoint).toMatch(/export "\$var=\$SECRET_DST\/\$name"/);
    // 指针重写之后还要以 nodejs 身份验证可读，不能只信 root 的 chmod 返回值
    expect(entrypoint).toMatch(/verify_file_pointers nodejs_can_read/);
  });

  test('root 阶段结束必须 su-exec 降权；非 root 启动只校验可读性', () => {
    expect(entrypoint).toMatch(/exec su-exec nodejs:nodejs dumb-init -- "\$@"/);
    expect(entrypoint).toMatch(/verify_file_pointers test -r/);
    expect(entrypoint).toMatch(/exec dumb-init -- "\$@"/);
    // 不允许在 root 分支直接 exec 应用（那会让应用以 root 运行）
    expect(entrypoint).not.toMatch(/exec node /);
  });

  test('HOME/USER/LOGNAME 按 nodejs 重设（root 启动时 Docker 会把 HOME 设为 /root）', () => {
    // 2026-10-31：解析方式从 `grep … | cut …` 改成纯 shell 的 `IFS=: read`（外部命令缺失时
    // 命令替换只剩空串而 set -e 不触发，见 tests/deploy/appEntrypointHomePasswd.test.js）。
    // 这里只钉"仍然按 passwd 取值 + 仍然 export 成 nodejs"这条形状，实现细节交给那份行为级用例。
    expect(entrypoint).toMatch(/IFS=: read -r name _pw _uid _gid _gecos home _shell/);
    expect(entrypoint).toMatch(/done < \/etc\/passwd/);
    expect(entrypoint).toMatch(/export HOME="\$nodejs_home"/);
    expect(entrypoint).toMatch(/export USER=nodejs/);
    expect(entrypoint).toMatch(/export LOGNAME=nodejs/);
  });
});

describe('Dockerfile：镜像默认非 root，入口脚本负责权限适配', () => {
  test('安装 su-exec 并把入口脚本放进镜像', () => {
    expect(dockerfile).toMatch(/apk add --no-cache dumb-init tzdata su-exec/);
    expect(dockerfile).toMatch(
      /^COPY docker\/app-entrypoint\.sh \/usr\/local\/bin\/app-entrypoint\.sh$/m
    );
    expect(dockerfile).toMatch(/chmod 0755 \/usr\/local\/bin\/app-entrypoint\.sh/);
  });

  test('镜像默认 USER nodejs；ENTRYPOINT 是入口脚本，不是直接 dumb-init', () => {
    expect(dockerfile).toMatch(/^USER nodejs$/m);
    expect(dockerfile).toMatch(/^ENTRYPOINT \["\/usr\/local\/bin\/app-entrypoint\.sh"\]$/m);
    expect(dockerfile).not.toMatch(/^ENTRYPOINT \["dumb-init", "--"\]$/m);
  });
});

describe('compose app 服务：最小能力集 + tmpfs 副本', () => {
  test('以 root 启动入口脚本，但仅补四项能力；其余仍全部丢弃', () => {
    expect(appBlock).toMatch(/^ {4}user:\s*['"]?0:0['"]?\s*$/m);
    expect(listItems(appBlock, 'cap_drop')).toEqual(['ALL']);
    expect(listItems(appBlock, 'cap_add').sort()).toEqual(
      ['CHOWN', 'DAC_OVERRIDE', 'SETGID', 'SETUID'].sort()
    );
    // 不补 FOWNER：脚本先 chmod 再 chown，故意不依赖它
    expect(listItems(appBlock, 'cap_add')).not.toContain('FOWNER');
    expect(appBlock).toMatch(/^ {4}read_only:\s*true$/m);
  });

  test('tmpfs 必须包含 /run/app-secrets；副本不落盘、不进镜像层', () => {
    expect(listItems(appBlock, 'tmpfs')).toEqual(
      expect.arrayContaining(['/tmp', '/run/app-secrets'])
    );
  });

  test('compose 的 *_FILE 仍指向 /run/secrets（挂载点由 Docker 定义，重写在入口脚本里）', () => {
    expect(appBlock).toMatch(/^ {6}- JWT_SECRET_FILE=\/run\/secrets\/jwt_secret$/m);
    expect(appBlock).toMatch(/^ {6}- REDIS_PASSWORD_FILE=\/run\/secrets\/redis_password$/m);
  });

  test('解析器自证：合成块缺 tmpfs / 多补 SYS_ADMIN 时判据会红', () => {
    const GOOD = [
      'services:',
      '  app:',
      '    user: "0:0"',
      '    read_only: true',
      '    cap_drop:',
      '      - ALL',
      '    cap_add:',
      '      - CHOWN',
      '      - DAC_OVERRIDE',
      '      - SETGID',
      '      - SETUID',
      '    tmpfs:',
      '      - /tmp',
      '      - /run/app-secrets',
      '    secrets:',
      '      - jwt_secret',
      '',
    ].join('\n');
    const good = serviceBlockFrom(GOOD, 'app');
    expect(good).not.toBeNull();
    expect(listItems(good, 'cap_add')).toEqual(
      expect.arrayContaining(['CHOWN', 'DAC_OVERRIDE', 'SETGID', 'SETUID'])
    );
    expect(listItems(good, 'tmpfs')).toContain('/run/app-secrets');

    const evil = GOOD.replace('      - /run/app-secrets\n', '').replace(
      '      - SETUID\n',
      '      - SETUID\n      - SYS_ADMIN\n'
    );
    const bad = serviceBlockFrom(evil, 'app');
    expect(listItems(bad, 'tmpfs')).not.toContain('/run/app-secrets');
    expect(listItems(bad, 'cap_add')).toContain('SYS_ADMIN');
  });
});
