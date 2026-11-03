// 临时授予（PrivilegeGrant）存的是权限码字符串，没有 populate 可挂 match：码被停用后持有者仍能
// 按码精确匹配放行（最长 168h），且日志里看不出这层豁免。判据必须与角色路径（PERMISSION_POPULATE
// 的 match:{status:'active'}）同源，故收敛到本模块，禁止在调用点另写名单；软删由模型默认读过滤排除。
const Permission = require('../models/Permission');

async function activeCodesOf(codes) {
  const docs = await Permission.find({ code: { $in: codes }, status: 'active' }, 'code').lean();
  return new Set(docs.map((doc) => String(doc.code).toLowerCase()));
}

function pruneBucket(bucket, active) {
  bucket.codes = bucket.codes.filter((code) => active.has(String(code).toLowerCase()));
}

async function dropInactiveGrantCodes(buckets) {
  const codes = [...new Set([...buckets.values()].flatMap((bucket) => bucket.codes))];
  if (codes.length === 0) return;
  const active = await activeCodesOf(codes);
  for (const bucket of buckets.values()) pruneBucket(bucket, active);
}

module.exports = { dropInactiveGrantCodes };
