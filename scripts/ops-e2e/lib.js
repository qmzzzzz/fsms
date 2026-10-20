'use strict';

const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');

/**
 * 一次旅程的步骤记账。
 *
 * requiredMarkers 与 production-drill/e2e-smoke 同一口径：只写进日志、不做断言的步骤
 * 会在被删掉时照样全绿；这里要求关键步骤名至少被执行过一次。
 */
function createJourney(id, requiredMarkers) {
  const ran = [];
  const failures = [];

  async function step(name, fn) {
    ran.push(name);
    try {
      await fn();
      console.log(`  ok ${name}`);
    } catch (err) {
      failures.push(`${name}：${err.message}`);
      console.error(`  FAIL ${name}：${err.message}`);
    }
  }

  function finish() {
    for (const marker of requiredMarkers) {
      if (!ran.some((name) => name.includes(marker))) {
        failures.push(`门禁自证：关键步骤未执行（${marker}）`);
      }
    }
    if (failures.length > 0) {
      console.error(`[ops-e2e:${id}] 失败 ${failures.length} 项：`);
      for (const f of failures) console.error(`  - ${f}`);
      return false;
    }
    console.log(`[ops-e2e:${id}] 通过（${ran.length} 步）`);
    return true;
  }

  return { step, finish };
}

/** 轮询直到 fn 返回真值；用于启动/健康检查，不用固定睡眠猜时序 */
async function waitFor(fn, { timeoutMs = 30000, intervalMs = 100, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value) return value;
    } catch (err) {
      lastError = err;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(
    `${label} 在 ${timeoutMs}ms 内未达成` +
      (lastError ? `（最后一次错误：${lastError.message}）` : '')
  );
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function listFiles(dir, pattern) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((name) => pattern.test(name))
    .map((name) => path.join(dir, name))
    .sort();
}

/** 以子进程执行 Node 脚本，返回 { status, stdout, stderr }；不抛错，由调用方断言 */
function runNode(script, args, { env = process.env, timeoutMs = 60000, cwd } = {}) {
  const { spawnSync } = require('child_process');
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd,
    env,
    encoding: 'utf8',
    timeout: timeoutMs,
    windowsHide: true,
  });
  const spawnError = result.error ? `spawn error: ${result.error.message}` : '';
  return {
    status: result.status,
    signal: result.signal,
    stdout: String(result.stdout || ''),
    stderr: String(result.stderr || '') + (spawnError ? `\n${spawnError}` : ''),
  };
}

function assertExitOk(result, label) {
  assert.equal(
    result.status,
    0,
    `${label} 退出码 ${result.status}（signal=${result.signal || '无'}）\n` +
      `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`
  );
}

/**
 * runNode 的非阻塞版本。**调用方本进程里跑着 HTTP 服务时必须用它**：
 * spawnSync 会阻塞父进程事件循环，父进程里的服务无法 accept，
 * 子进程的请求只能等到超时（实测：探针 5s 超时且服务端一条请求都没收到）。
 */
function runNodeAsync(script, args, { env = process.env, timeoutMs = 60000, cwd } = {}) {
  const { spawn } = require('child_process');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd,
      env,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({
        status: null,
        signal: null,
        stdout,
        stderr: `${stderr}spawn error: ${err.message}`,
      });
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        status: timedOut ? null : code,
        signal: timedOut ? 'TIMEOUT' : signal,
        stdout,
        stderr: timedOut ? `${stderr}\n超时 ${timeoutMs}ms` : stderr,
      });
    });
  });
}

module.exports = {
  assert,
  createJourney,
  waitFor,
  readJson,
  listFiles,
  runNode,
  runNodeAsync,
  assertExitOk,
};
