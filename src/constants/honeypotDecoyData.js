'use strict';

/**
 * 蜜罐影子数据面的**合成数据表**（P1）
 *
 * 与判定逻辑（constants/honeypotDecoy.js）分开的理由只有一条：体积。这些行是纯数据
 * （每行一条诱饵记录，prettier 会把长行拆成多行对象），塞在同一个文件里会让它越过
 * max-lines 300 的棘轮基线——而棘轮只许降不许升，所以「加两条诱饵记录」不该变成
 * 「必须改基线」。逻辑与数据分家后，两边都各自在 300 行内。
 *
 * 约束（判据在 src/tests/ci/honeypotDecoyLedger.test.js）：每条记录的 _id 必须以
 * HONEYPOT_DECOY_ID_PREFIX 开头且**不是**合法 ObjectId——撞号即等于让陷阱会话读到真记录；
 * 所有表整体冻结，运行期改不动。
 */

const {
  DECOY_ORG,
  HONEYPOT_DECOY_ID_PREFIX,
  OFFSET_SUFFIX,
  frozenRows,
} = require('./honeypotDecoyIds');
const { DECOY_SELF, DECOY_USERS } = require('./honeypotDecoyUsers');
const {
  DECOY_PERMISSION_ROWS,
  DECOY_PERMISSIONS,
  DECOY_ROLE_CODES,
  DECOY_ROLES,
} = require('./honeypotDecoyRbac');
const { DECOY_DEVICES } = require('./honeypotDecoyDevices');
const { DECOY_ALARMS } = require('./honeypotDecoyAlarms');
const { DECOY_INSPECTIONS } = require('./honeypotDecoyInspections');

module.exports = {
  DECOY_ALARMS,
  DECOY_DEVICES,
  DECOY_INSPECTIONS,
  DECOY_ORG,
  DECOY_PERMISSION_ROWS,
  DECOY_PERMISSIONS,
  DECOY_ROLE_CODES,
  DECOY_ROLES,
  DECOY_SELF,
  DECOY_USERS,
  HONEYPOT_DECOY_ID_PREFIX,
  OFFSET_SUFFIX,
  frozenRows,
};
