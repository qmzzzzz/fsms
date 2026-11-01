/**
 * 隐私告知的**前端侧常量**（审计一-7）
 *
 * 为什么前端要自己持有一份：告知版本号与范围清单在提交前就要显示（勾选框旁必须能看到
 * "同意的是哪一版、覆盖哪些数据"），无法等到提交后由后端回吐；而"注册即表示同意"
 * 正是本轮要关闭的形态，所以界面必须在**勾选之前**把版本与范围写清楚。
 *
 * 单一事实来源仍在后端（services/consentService.PRIVACY_NOTICE_VERSION 与
 * constants/dataClassification.CONSENT_SCOPES）。手抄这一份的漂移由
 * web-admin/src/tests/utils/privacyNoticeParity.test.js 双向对拍：后端升版或增减 notice 范围
 * 而前端没跟，测试即红——不靠口头纪律。
 */
export const PRIVACY_NOTICE_VERSION = '2026-11-01'

/** 本次告知覆盖的范围键（与后端 CONSENT_SCOPES 中 basis='notice' 的项一一对应） */
export const PRIVACY_NOTICE_SCOPES = Object.freeze(['account', 'avatar', 'device'])
