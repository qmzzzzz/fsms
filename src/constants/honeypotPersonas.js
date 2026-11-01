const { normalizeCanaryUsername } = require('./canaryAccounts'); // 归一化与诱饵名/哨兵名同一套（trim + 小写），否则 ROOT 与 root 会派出两份画像

const PERSONA_SURNAMES = Object.freeze([
  '王',
  '李',
  '张',
  '刘',
  '陈',
  '杨',
  '黄',
  '赵',
  '周',
  '吴',
  '徐',
  '孙',
  '马',
  '朱',
  '胡',
  '林',
  '郭',
  '何',
  '高',
  '罗',
  '梁',
  '宋',
  '唐',
  '许',
]); // 常见姓氏池：只求「像本单位的普通员工」，不求真实
const PERSONA_GIVEN_NAMES = Object.freeze([
  '建国',
  '志强',
  '秀英',
  '伟',
  '敏',
  '静',
  '磊',
  '洋',
  '勇',
  '艳',
  '杰',
  '娟',
  '涛',
  '明',
  '超',
  '霞',
  '平',
  '刚',
  '桂英',
  '芳',
  '立新',
  '海燕',
  '振华',
  '晓东',
  '文博',
  '春梅',
  '永强',
  '丽华',
]); // 两字/三字混排：全部取自同一代际，避免出现一眼假的名字
const PERSONA_DEPARTMENTS = Object.freeze([
  '消防中控室',
  '安防运维部',
  '设备维保部',
  '信息中心',
  '物业管理部',
  '安全监察部',
  '后勤保障部',
  '综合办公室',
  '技术支撑部',
  '应急指挥中心',
]); // 部门池与蜜罐影子数据面的口径一致（中控室/维保部等），但用全称，避免与诱饵行同名

const hashOf = (text) => {
  let hash = 2166136261; // FNV-1a 32 位：只为「同名恒同画像」，不做密码学承诺
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
};

const candidateOf = (name, attempt) => {
  const salt = name + '#' + attempt; // attempt 参与盐：撞名时换一批候选，而不是在名字后面加「_2」这种一眼异常的尾巴
  const pick = (pool, field) => pool[hashOf(salt + ':' + field) % pool.length];
  return {
    realName: pick(PERSONA_SURNAMES, 'surname') + pick(PERSONA_GIVEN_NAMES, 'given'),
    department: pick(PERSONA_DEPARTMENTS, 'department'),
  };
};

const PERSONA_MAX_ATTEMPTS = 64; // 撞名重试上限：每轮都换盐，11 个诱饵名实测零碰撞
const deriveHoneypotPersona = (name, takenRealNames = []) => {
  const normalized = normalizeCanaryUsername(name) || String(name ?? '');
  const taken = new Set(takenRealNames.map((value) => String(value)));
  for (let attempt = 0; attempt < PERSONA_MAX_ATTEMPTS; attempt += 1) {
    const persona = candidateOf(normalized, attempt);
    if (!taken.has(persona.realName)) return persona;
  }
  return candidateOf(normalized, PERSONA_MAX_ATTEMPTS); // 兜底：候选池 24×28 远大于诱饵条数，走不到这里；真走到了也宁可重名，绝不因画像撞名而让物化失败
};

module.exports = {
  PERSONA_DEPARTMENTS,
  PERSONA_GIVEN_NAMES,
  PERSONA_SURNAMES,
  deriveHoneypotPersona,
};
