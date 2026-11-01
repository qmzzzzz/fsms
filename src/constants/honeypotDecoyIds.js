'use strict';

const HONEYPOT_DECOY_ID_PREFIX = 'hp-'; // 合成 id：与真实 ObjectId（24 位十六进制）形态必然不相交，任何时刻都不可能与真记录撞号
const DECOY_ORG = '临江化工园区消防维保中心';
const frozenRows = (rows) => Object.freeze(rows.map((row) => Object.freeze(row)));
const OFFSET_SUFFIX = 'OffsetMin';

module.exports = { DECOY_ORG, HONEYPOT_DECOY_ID_PREFIX, OFFSET_SUFFIX, frozenRows };
