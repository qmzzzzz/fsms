/** 错误响应禁缓存（P0-1）的统一出口：429/403 这类出口绕过 ApiResponse 直接写响应，散写会漏。 */
/** 判据：出口登记表要求 .status(code) 的接收者必须是本函数（tests/middleware/errorResponseNoStore.test.js）。 */
const setNoStore = (res) => {
  res.setHeader('Cache-Control', 'no-store');
  return res;
};

module.exports = { setNoStore };
