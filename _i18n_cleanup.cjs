const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, 'web-admin');

// 1. 删 en-US 的 3 个死条目
let s = fs.readFileSync(path.join(ROOT, 'src/i18n/locales/en-US.js'), 'utf8');
for (const k of [
  '关闭后，仅管理员可创建新用户，公开注册接口将返回 403',
  '开启后，登录时需输入图形验证码；默认关闭',
  '开启后，注册时需输入图形验证码；默认开启',
]) {
  const re = new RegExp("^ {2}'" + k + "': .*,\r?\n", 'gm');
  if (!re.test(s)) {
    console.error('NOT FOUND:', k);
    process.exit(1);
  }
  s = s.replace(re, '');
}
fs.writeFileSync(path.join(ROOT, 'src/i18n/locales/en-US.js'), s);

// 2. 删 legacy 兼容层文件
fs.rmSync(path.join(ROOT, 'src/i18n/locales/legacy-raw-zh.js'), { force: true });
fs.rmSync(path.join(ROOT, 'src/i18n/locales/legacy-raw-en.js'), { force: true });
console.log('死键删除 + legacy 兼容层已删除');
