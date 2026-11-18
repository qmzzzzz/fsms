/**
 * API 基路径（单一事实来源，零依赖叶子模块）
 *
 * axios 实例（utils/api.js）、登录公钥请求（utils/loginCipher.js）、
 * 版本探测（utils/versionWatcher.js）必须使用同一前缀。三处各自派生时口径一旦
 * 漂移，分域或子路径部署（VITE_API_BASE_URL）下总有一类请求打到错误前缀，
 * 且多以「静默失败」形态出现（如版本探测失败按纪律静默，无人发现）。
 */
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'
