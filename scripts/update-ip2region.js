/**
 * ip2region.xdb 数据更新脚本（零依赖，node 内置模块实现）
 *
 * 用法：
 *   node scripts/update-ip2region.js            # 拉取最新数据并原子替换 src/data/ip2region.xdb
 *   node scripts/update-ip2region.js --check    # 只打印当前数据的构建日期与探针结果，不做任何改动
 *
 * 数据源按顺序尝试（任一成功即停），全部失败时退出码 1：
 *   1. Gitee   raw（国内直连最快）
 *   2. GitHub  raw（官方仓库）
 *   3. jsDelivr CDN（GitHub 镜像）
 *   4. npm registry 上打包了官方数据的 ip2region-ts 包（公司代理常只放行 npm）
 *
 * 下载内容不做「信任即用」：先过结构校验（version=2、指针范围、长度下限），
 * 再跑三个探针查询（阿里 DNS=中国、Google DNS=美国、环回=内网IP），探针语义
 * 源自数据生成器的稳定事实而非某条具体记录——防止把 HTML 错误页/截断文件
 * 当成数据替换进仓库（本仓 check:utf8 等门禁也不会拦二进制，只能靠这里自证）。
 */
const fs = require('fs');
const https = require('https');
const zlib = require('zlib');

const searcher = require('../src/utils/ip2regionSearcher');

const TARGET = searcher.DATA_FILE;
const USER_AGENT = 'fsms-update-ip2region/1.0';

const SOURCES = [
  {
    name: 'Gitee raw',
    url: 'https://gitee.com/lionsoul/ip2region/raw/master/data/ip2region.xdb',
  },
  {
    name: 'GitHub raw',
    url: 'https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region.xdb',
  },
  {
    name: 'jsDelivr CDN',
    url: 'https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region.xdb',
  },
];

/** 探针查询：期望命中串包含 expect 子串（这些事实随数据版本漂移的概率极低） */
const PROBES = [
  { ip: '223.5.5.5', expect: '中国' }, // 阿里公共 DNS（浙江杭州）
  { ip: '8.8.8.8', expect: '美国' }, // Google 公共 DNS
  { ip: '127.0.0.1', expect: '内网IP' }, // 环回地址：数据生成器恒标内网
];

/** 打印数据的构建日期与探针结果；结构非法时抛错 */
const verifyBuffer = (buffer, label) => {
  const handle = searcher.loadFromBuffer(buffer);
  const createTime = new Date(handle.buffer.readUInt32LE(4) * 1000);
  for (const probe of PROBES) {
    const raw = searcher.searchRaw(handle, probe.ip);
    if (typeof raw !== 'string' || !raw.includes(probe.expect)) {
      throw new Error(
        `${label} 探针未通过：${probe.ip} → ${JSON.stringify(raw)}（期望含「${probe.expect}」）`
      );
    }
  }
  console.log(
    `${label} 校验通过：版本 v${handle.version}，构建于 ${createTime.toISOString().slice(0, 10)}`
  );
  return handle;
};

/** HTTPS GET（跟随最多 3 次重定向），resolve(Buffer) */
const httpsGet = (url, redirects = 0) =>
  new Promise((resolve, reject) => {
    if (redirects > 3) {
      reject(new Error('重定向次数超限'));
      return;
    }
    const req = https.get(url, { headers: { 'User-Agent': USER_AGENT } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        httpsGet(new URL(res.headers.location, url).toString(), redirects + 1).then(
          resolve,
          reject
        );
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(60000, () => {
      req.destroy(new Error('响应超时（60s）'));
    });
  });

/** 从 npm 包 tarball（gzip 的 tar）中提取 data/ip2region.xdb */
const extractXdbFromNpmTarball = async () => {
  const metaBuf = await httpsGet('https://registry.npmjs.org/ip2region-ts/latest');
  const tarballUrl = JSON.parse(metaBuf.toString('utf-8')).dist.tarball;
  if (!tarballUrl) throw new Error('npm 元数据缺 dist.tarball');
  console.log(`  npm tarball: ${tarballUrl}`);
  const raw = await httpsGet(tarballUrl);
  const tar = zlib.gunzipSync(raw);

  // 最小 tar 解析：512B 头（名字在 [0,100)，大小在 [124,136) 八进制）+ 512B 对齐的数据块
  const XDB_NAME = 'package/data/ip2region.xdb';
  for (let off = 0; off + 512 <= tar.length;) {
    const nameBuf = tar.subarray(off, off + 100);
    if (nameBuf.every((b) => b === 0)) break; // 结束块
    const name = nameBuf.toString('utf-8').replace(/\0.*$/, '');
    const size =
      parseInt(
        tar
          .subarray(off + 124, off + 136)
          .toString('utf-8')
          .replace(/\0.*$/, '')
          .trim(),
        8
      ) || 0;
    const dataOff = off + 512;
    if (name === XDB_NAME) {
      return tar.subarray(dataOff, dataOff + size);
    }
    off = dataOff + Math.ceil(size / 512) * 512;
  }
  throw new Error(`tar 包内未找到 ${XDB_NAME}`);
};

const main = async () => {
  if (process.argv.includes('--check')) {
    verifyBuffer(fs.readFileSync(TARGET), '当前数据');
    return;
  }

  const attempts = [...SOURCES.map((s) => () => httpsGet(s.url)), extractXdbFromNpmTarball];
  let buffer = null;
  for (let i = 0; i < attempts.length; i++) {
    const label = i < SOURCES.length ? SOURCES[i].name : 'npm tarball (ip2region-ts)';
    try {
      console.log(`尝试数据源：${label} ...`);
      buffer = await attempts[i]();
      if (buffer.length < 1024 * 1024)
        throw new Error(`文件过小（${buffer.length} 字节），疑似错误页`);
      verifyBuffer(buffer, label);
      break;
    } catch (err) {
      console.warn(`  ${label} 失败：${err.message}`);
      buffer = null;
    }
  }
  if (!buffer) {
    console.error('全部数据源失败，未做任何改动。请检查网络后重试。');
    process.exitCode = 1;
    return;
  }

  // 原子替换：先写同目录临时文件再 rename，中途断电/被杀不会留下半截数据
  const tmp = `${TARGET}.tmp`;
  fs.writeFileSync(tmp, buffer);
  fs.renameSync(tmp, TARGET);
  console.log(`已更新 ${TARGET}（${buffer.length} 字节）。建议提交本次数据变更。`);
};

main().catch((err) => {
  console.error(`更新失败：${err.message}`);
  process.exitCode = 1;
});
