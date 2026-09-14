const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, 'web-admin');

// eslint 报出的重复键（插入副本在前、既有键在后；删除插入副本）
const DUP = {
  common: ['cancel', 'delete', 'pleaseSelect'],
  inspection: [
    'inspectionTitle',
    'inspectionType',
    'result',
    'planStartTime',
    'planEndTime',
    'checkItems',
    'reviewResult',
    'reviewComment',
    'approved',
    'rejected',
    'normal',
    'abnormal',
    'partial',
    'typeDaily',
    'typeWeekly',
    'typeMonthly',
    'typeQuarterly',
    'typeAnnual',
    'typeSpecial',
  ],
};

for (const dict of ['src/i18n/locales/zh-CN.js', 'src/i18n/locales/en-US.js']) {
  const p = path.join(ROOT, dict);
  const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/);
  let removed = 0;
  for (const [ns, keys] of Object.entries(DUP)) {
    const nsLine = lines.findIndex((l) => new RegExp(`^ {2}${ns}: \\{`).test(l));
    if (nsLine === -1) throw new Error(`ns not found: ${ns}`);
    // 在 ns 块内（到下一个顶层键行）找重复键的行
    let end = lines.length;
    for (let i = nsLine + 1; i < lines.length; i++) {
      if (/^ {2}\w/.test(lines[i]) && !/^ {4}/.test(lines[i])) {
        end = i;
        break;
      }
    }
    for (const key of keys) {
      const occurrences = [];
      for (let i = nsLine + 1; i < end; i++) {
        if (new RegExp(`^ {4}${key}:`).test(lines[i])) occurrences.push(i);
      }
      if (occurrences.length < 2) continue;
      // 删除第一处（脚本注入的副本）
      lines[occurrences[0]] = null;
      removed++;
    }
  }
  fs.writeFileSync(p, lines.filter((l) => l !== null).join('\r\n'));
  console.log(`${dict}: removed ${removed} duplicate entries`);
}
console.log('DONE');
