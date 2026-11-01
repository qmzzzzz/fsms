/**
 * 应用内一键升级的部署侧契约（2026-10-30）
 *
 * 这条链路跨四个边界，任何一处断了都表现为「按钮点了没反应」：
 *   容器写入队列（bind mount + 权限）→ 宿主 timer 拉起代理 → 代理执行固定脚本
 *   → 应用轮询 status/。
 *
 * 本文件只做静态断言（本地没有部署机）：锁住挂载点/环境变量/入口脚本权限适配/
 * systemd 单元的存在与关键开关，防止后续「整理 compose」时把队列悄悄删掉。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
const entrypoint = fs.readFileSync(path.join(ROOT, 'docker/app-entrypoint.sh'), 'utf8');
const service = fs.readFileSync(
  path.join(ROOT, 'deployment/systemd/fsms-hot-upgrade-agent.service'),
  'utf8'
);
const timer = fs.readFileSync(
  path.join(ROOT, 'deployment/systemd/fsms-hot-upgrade-agent.timer'),
  'utf8'
);

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

const app = serviceBlockFrom(compose, 'app');
const green = serviceBlockFrom(compose, 'app-green');

describe('compose：队列挂载与环境变量', () => {
  test('前提自证：切到了 app / app-green 块', () => {
    expect(app).not.toBeNull();
    expect(green).not.toBeNull();
    expect(app).toMatch(/^ {4}image:\s+\$\{APP_IMAGE/m);
    expect(green).toMatch(/extends:\s*\n\s+service:\s*app/);
  });

  test('app 把宿主队列目录挂到固定容器路径（宿主路径可配，容器路径不可变）', () => {
    expect(app).toMatch(
      /^ {6}- \$\{UPGRADE_QUEUE_HOST_DIR:-\/var\/lib\/fsms\/upgrade\}:\/var\/lib\/fsms\/upgrade$/m
    );
    // 容器内路径与 src/config/upgrade.js 的默认值一致；写成别的路径会让
    // 「挂载成功但应用看空目录」这种最难排查的形态出现。
    expect(app).toMatch(/^ {6}- UPGRADE_QUEUE_DIR=\/var\/lib\/fsms\/upgrade$/m);
  });

  test('升级相关环境变量在 app 段可达（空白名单 = 全拒的语义由该变量承载）', () => {
    for (const line of [
      'UPGRADE_ENABLED=${UPGRADE_ENABLED:-false}',
      'HOT_UPGRADE_REGISTRY_ALLOWLIST=${HOT_UPGRADE_REGISTRY_ALLOWLIST:-}',
      'UPGRADE_AGENT_STALE_SECONDS=${UPGRADE_AGENT_STALE_SECONDS:-120}',
      'UPGRADE_REQUEST_TTL_SECONDS=${UPGRADE_REQUEST_TTL_SECONDS:-1800}',
      'UPGRADE_HISTORY_LIMIT=${UPGRADE_HISTORY_LIMIT:-10}',
    ]) {
      expect({ line, present: app.includes(`- ${line}`) }).toMatchObject({
        line,
        present: true,
      });
    }
  });

  test('备色显式声明 DEPLOY_COLOR=green（容器内两色都监听 3000，PORT 区分不了颜色）', () => {
    expect(green).toMatch(/^ {6}- DEPLOY_COLOR=green$/m);
  });
});

describe('入口脚本：队列目录权限适配', () => {
  test('root 阶段创建四个子目录，且只有 requests 交给 nodejs（其余写权限留给 root 代理）', () => {
    expect(entrypoint).toMatch(/^prepare_upgrade_queue\(\)/m);
    for (const sub of ['requests', 'status', 'processing', 'rejected']) {
      expect(entrypoint).toContain(`"$QUEUE_DIR/${sub}"`);
    }
    // 应用只写 requests：不改属主会在 fs.access(W_OK) 判据处直接拒绝
    expect(entrypoint).toMatch(/chown nodejs:nodejs "\$QUEUE_DIR\/requests"/);
    expect(entrypoint).toMatch(
      /find "\$QUEUE_DIR\/requests" -xdev -type f -exec chown nodejs:nodejs/
    );
    // 其余三个目录若也 chown nodejs，应用被攻陷后可删 .agent.lock（升级永久 busy）、
    // 伪造 status 为 succeeded（界面假成功）、清空 rejected（验签失败留证消失）。
    expect(entrypoint).not.toMatch(/chown nodejs:nodejs "\$QUEUE_DIR\/status"/);
    expect(entrypoint).not.toMatch(/chown nodejs:nodejs "\$QUEUE_DIR\/processing"/);
    expect(entrypoint).toMatch(/chown root:root "\$QUEUE_DIR\/rejected"/);
    // status/processing 要给应用读：属主 root、属组 nodejs、0640
    expect(entrypoint).toMatch(
      /chgrp nodejs "\$QUEUE_DIR" "\$QUEUE_DIR\/status" "\$QUEUE_DIR\/processing"/
    );
    expect(entrypoint).toMatch(
      /find "\$QUEUE_DIR\/status" "\$QUEUE_DIR\/processing" -xdev -type f \\/
    );
    // 属主矩阵的另一半：status/processing 的**根属主**必须收回 root（只 chgrp 不够——
    // 属主是 nodejs 时应用可以对目录里的文件 unlink/rename，锁与状态文件照样被毁）。
    expect(entrypoint).toMatch(/chown root:root \\\n(?:.*\n)*?\s*"\$QUEUE_DIR\/rejected"/);
    // 目录权限：rejected 只有 root 能进（0700），status/processing 应用要能进来读（0750）。
    expect(entrypoint).toMatch(/chmod 0700 "\$QUEUE_DIR\/rejected"/);
    expect(entrypoint).toMatch(/chmod 0750 "\$QUEUE_DIR\/status"/);
    expect(entrypoint).toMatch(/chmod 0750 "\$QUEUE_DIR\/processing"/);
    // 首启前留下的旧文件不带新矩阵，已有文件也要就地修正归属与权限（逐文件，不递归）。
    expect(entrypoint).toMatch(
      /find "\$QUEUE_DIR\/status" "\$QUEUE_DIR\/processing" -xdev -type f \\\n\s*-exec chown root:nodejs \{\} \+ -exec chmod 0640 \{\} \+/
    );
    expect(entrypoint).toMatch(
      /find "\$QUEUE_DIR\/rejected" -xdev -type f \\\n\s*-exec chown root:root \{\} \+ -exec chmod 0600 \{\} \+/
    );
    // 系统目录保护不能只钉 /etc：/var/lib 是最可能被误配成队列根的位置。
    expect(entrypoint).toMatch(/\/var\/lib \|/);
    // chown -R 会跟随符号链接（应用被攻陷后可在队列里放指向宿主关键文件的链接）
    expect(entrypoint).not.toMatch(/chown -R\s+nodejs:nodejs\s+"\$QUEUE_DIR"/);
  });

  test('chmod 之前先收回 root 属主：cap_drop: ALL 无 FOWNER，对 nodejs 的目录 chmod 会 EPERM', () => {
    // 反例是真实故障形态：第一轮 chown 后进程崩溃/重启，第二轮 chmod 0700 直接 EPERM，
    // set -eu 让入口退出 ⇒ 升级窗口里起不来的正是最需要起来的那个容器。
    const chownAt = entrypoint.indexOf('chown root:root \\');
    const chmodAt = entrypoint.indexOf('chmod 0700 "$QUEUE_DIR/requests"');
    expect(chownAt).toBeGreaterThan(-1);
    expect(chmodAt).toBeGreaterThan(chownAt);
    // 允许行尾的 && ：权限适配块必须逐条 && 串联（`{ a; b; c; }` 的退出码只取最后一条，
    // 中间一条 EPERM 会被静默吞掉，见 docker/app-entrypoint.sh 该块上方注释与
    // appEntrypointQueuePermFallback.test.js 的真跑判据）。
    // `(?: &&)?` 是可选的 ⇒ 对「有 &&」「没有 &&」都 true，判别力为零（2026-10-30 第二轮审计
    // 实测：删掉 `&&` 后本用例照样绿）。逐条 && 是这条不变量本身，必须写成必需匹配；
    // 行为侧由 appEntrypointQueuePermFallback.test.js 的「第 N 条失败」注入单独钉住。
    expect(entrypoint).toMatch(/chmod 0750 "\$QUEUE_DIR" &&$/m);
    // 前提自证：整块 8 条命令之间有 7 个 &&（少一个就说明有人把它改回了逐行并列）
    expect((entrypoint.match(/ &&\n/g) || []).length).toBe(7);
  });

  test('UPGRADE_QUEUE_DIR 指向系统目录时拒绝改属主（否则把宿主 /etc 交给 UID 1001）', () => {
    expect(entrypoint).toMatch(/\/etc \| \/etc\/\*/);
    expect(entrypoint).toMatch(/已跳过权限适配/);
    expect(entrypoint).toMatch(/必须是绝对路径/);
  });

  test('目录不存在时静默跳过（本地 docker run 未挂载也能起服务）', () => {
    expect(entrypoint).toMatch(/\[ -d "\$QUEUE_DIR" \] \|\| return 0/);
  });
});

describe('systemd：代理单元', () => {
  test('oneshot + timer，且 timer 从服务结束开始计时（升级期间不叠加实例）', () => {
    expect(service).toMatch(/^Type=oneshot$/m);
    expect(service).toMatch(/ExecStart=\/usr\/bin\/node .*hotUpgradeAgent\.js --once$/m);
    expect(service).toMatch(/^EnvironmentFile=\/etc\/fsms\/hot-upgrade\.env$/m);
    // 升级最坏耗时远超默认服务超时，必须显式放宽
    expect(service).toMatch(/^TimeoutStartSec=2h$/m);
    expect(timer).toMatch(/^OnUnitInactiveSec=15s$/m);
    expect(timer).toMatch(/^Unit=fsms-hot-upgrade-agent\.service$/m);
  });

  test('示例 env 不包含真实密钥，只给文件指针', () => {
    const example = fs.readFileSync(
      path.join(ROOT, 'deployment/systemd/hot-upgrade.env.example'),
      'utf8'
    );
    expect(example).toMatch(/^HMAC_SECRET_FILE=/m);
    expect(example).not.toMatch(/^HMAC_SECRET=/m);
    expect(example).not.toMatch(/sha256:[0-9a-f]{64}/);
  });
});
