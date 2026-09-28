/**
 * 数据范围判据：自己的记录永远在自己范围内（唯一例外 type:'none'）
 *
 * 起因：用户写路径新加了对象级范围闸（assertRecordInScope），而 User.createdBy 与
 * User.department 都是可选字段——播种账户（含内置 admin）与范围闸上线之前创建的存量账户
 * 都是 null。只比这两个字段会让 self/department 档管理员**连自己都被判为范围外**：
 * 改自己的资料 403、把自己锁定的那条 400 自我锁死防护也走不到。
 *
 * 反向对照同样是判据的一部分：GUEST（type:'none'）绝不能因为"这是自己的记录"就拿回数据权限，
 * 否则这条短路就从"修 fail-closed 的误伤"变成新的越权口子。
 *
 * 纯判据测试：`isRecordInScope` 不做任何 I/O，因此不起库、不起 app。
 */

const mongoose = require('mongoose');
const { isRecordInScope } = require('../../middleware/rbac');

const ME = new mongoose.Types.ObjectId();
const OTHER = new mongoose.Types.ObjectId();
const F = { ownerField: 'createdBy', departmentField: 'department' };

const selfDoc = (_id = ME, extra = {}) => ({ _id, ...extra });

const judge = (dataScope, doc, userId = String(ME)) =>
  isRecordInScope(dataScope, doc, { ...F, userId });

describe('self 范围：自己的记录恒在范围内', () => {
  test('createdBy 为 null 的自有记录仍算在范围内（修前为 false）', () => {
    expect(judge({ type: 'self' }, selfDoc())).toBe(true);
    expect(judge({ type: 'self' }, selfDoc(ME, { createdBy: null, department: null }))).toBe(true);
  });

  test('他人的记录不因短路放行', () => {
    expect(judge({ type: 'self' }, selfDoc(OTHER, { createdBy: OTHER }))).toBe(false);
    // 属主是自己但记录不是自己 ⇒ 仍按 createdBy 判，在范围内
    expect(judge({ type: 'self' }, selfDoc(OTHER, { createdBy: ME }))).toBe(true);
  });

  test('department 档同样含自己（未填部门的管理员至少能管自己）', () => {
    expect(judge({ type: 'department', department: null }, selfDoc())).toBe(true);
    // 同部门他人放行、异部门他人拒绝：短路不能把原判据一起废掉
    expect(
      judge({ type: 'department', department: 'A' }, selfDoc(OTHER, { department: 'A' }))
    ).toBe(true);
    expect(
      judge({ type: 'department', department: 'A' }, selfDoc(OTHER, { department: 'B' }))
    ).toBe(false);
  });

  test('反向对照：type:none 连自己的记录也不给（GUEST 不得因"是自己"拿回数据权限）', () => {
    expect(judge({ type: 'none' }, selfDoc())).toBe(false);
    expect(judge({ type: 'none' }, selfDoc(OTHER))).toBe(false);
  });

  test('all 与缺失判据方向不变（all 恒真、无判据恒假）', () => {
    expect(judge({ type: 'all' }, selfDoc(OTHER))).toBe(true);
    expect(judge(null, selfDoc())).toBe(false);
    expect(judge({ type: 'self' }, null)).toBe(false);
  });

  test('前提自证：短路只在"目标 id === 操作者 id"时生效（防把 String 比较写成恒真）', () => {
    const docWithHexId = selfDoc(ME);
    expect(judge({ type: 'self' }, docWithHexId, String(ME))).toBe(true);
    // 换一个操作者：同一条记录就不再是"自己的"
    expect(judge({ type: 'self' }, docWithHexId, String(OTHER))).toBe(false);
  });
});
