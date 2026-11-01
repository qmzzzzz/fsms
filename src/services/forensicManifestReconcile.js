/** 清单 ↔ 库对账（B-7）。verifyManifest 只证明「清单自身没被动过」（链连续、哈希可复算、尾未被截），**不证明**清单里说的那些记录真的还在库里——而「记录存在过」才是取证清单的核心承诺：攻击者根本不必改清单，直接 DELETE 几条 ForensicCap 就够。 判据口径（三种形态处置不同，不能混成一个布尔）：record_missing（清单声明 N 条、当天库里只有 M<N 条 ⇒ **篡改级**，红）；unmanifested（库里有、清单没记 ⇒ 只警告——清单写入失败也有计数可查，故不等于篡改，但数量异常膨胀意味着有人往库里塞记录）；no_manifest（当天清单根本不存在 ⇒ 无从对账，红，不能因为「没有证据」就判绿）。 【能力边界，必须如实说】只能定位到「少了 N 条」，**不能点名是哪几条**：清单每批只存逐条哈希的折叠值 hashesDigest，反推不出具体缺哪一个。要能点名就得在清单行里存全部 recordHash（单日约 4 万条 ⇒ 文件膨胀数十倍），取舍明确：宁可省空间 + 报准确差额，也不假装能点名。 只读：绝不写库、不改清单（对账动作本身不得成为证据链的一环）。 / / / */
const manifest = require('./forensicManifest');
const { businessDayBounds } = require('../constants/timezone');

const BATCH = 5000; // 分批发 IN：单日 4 万条量级时不能一次全塞进 $in，也不能退化成逐条查询

const chunk = (arr, size) => {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
};

/** @param {{dir?: string, date?: Date, model?: object}} opts model 可注入（用例传桩，生产用真模型） @returns {Promise<{ok:boolean, checked:number, declared:number, shortfall:number, unmanifested:number, problems:object[]}>} / / */
async function reconcileWithDb({ dir, date = new Date(), model = null } = {}) {
  const ForensicCapture = model || require('../models/ForensicCapture');
  const problems = [];
  const read = manifest.readManifest(dir ? { dir, date } : { date });
  if (!read.exists || read.entries.length === 0) {
    problems.push({
      type: 'no_manifest',
      line: null,
      message: '当日清单不存在或为空：无法与库对账（这不等于一致）',
    });
    return { ok: false, checked: 0, declared: 0, shortfall: 0, unmanifested: 0, problems };
  }

  const declared = read.entries.reduce((sum, e) => sum + (e.count || 0), 0);
  // 按**业务日**整天取库：seq 是 'RUN-序号' 字符串，字典序在 r-10/r-2 上会错，拿它做 $gte/$lte 区间会漏记录（B-2）。用 createdAt 落在业务日窗口内才可靠。
  const bounds = businessDayBounds(manifest.dateKeyOf(date));
  const docs = await ForensicCapture.find(
    { createdAt: { $gte: bounds.start, $lte: bounds.end } },
    { recordHash: 1, _id: 0 }
  ).lean();
  const present = new Set(docs.map((d) => d.recordHash).filter(Boolean));

  const shortfall = Math.max(0, declared - present.size);
  if (shortfall > 0) {
    problems.push({
      type: 'record_missing',
      line: null,
      message: `清单声明 ${declared} 条，当天库内只有 ${present.size} 条（少 ${shortfall} 条）`,
    });
  }
  const unmanifested = Math.max(0, present.size - declared);

  return {
    ok: problems.length === 0,
    checked: present.size,
    declared,
    shortfall,
    unmanifested,
    problems,
  };
}

module.exports = { reconcileWithDb, BATCH, chunk };
