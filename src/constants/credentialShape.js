'use strict';

const { isBreachedPassword } = require('../utils/helpers'); // 词干表判据唯一来源（本文件不新造词表）

const CREDENTIAL_SHAPE_FIELDS = Object.freeze([
  'credentialStemHits',
  'lengthBucket',
  'charsetClass',
]);

const LENGTH_BOUNDARIES = Object.freeze([8, 12, 16, 20]); // 档位下界：与口令强度校验的 PASSWORD_MIN_LENGTH 同源起点，档宽 4
const LENGTH_BUCKETS = Object.freeze(['lt8', '8-11', '12-15', '16-19', '20plus']);

const CHARSET_FLAGS = Object.freeze([
  Object.freeze(['l', (code) => code >= 97 && code <= 122]),
  Object.freeze(['u', (code) => code >= 65 && code <= 90]),
  Object.freeze(['d', (code) => code >= 48 && code <= 57]),
]); // 只剩「符号」是不在三条区间里的可打印字符：按补集判，避免自己维护一张符号表

const asText = (password) => (typeof password === 'string' ? password : '');

const lengthBucketOf = (password) => {
  const size = asText(password).length;
  const at = LENGTH_BOUNDARIES.findIndex((lower) => size < lower);
  return at === -1 ? LENGTH_BUCKETS[LENGTH_BUCKETS.length - 1] : LENGTH_BUCKETS[at];
};

const charsetClassOf = (password) => {
  const text = asText(password);
  let symbols = false;
  const flags = new Set();
  for (const char of text) {
    const code = char.codePointAt(0);
    const hit = CHARSET_FLAGS.find((item) => item[1](code));
    if (hit) flags.add(hit[0]);
    else symbols = true;
  }
  return CHARSET_FLAGS.filter((item) => flags.has(item[0]))
    .map((item) => item[0])
    .concat(symbols ? ['s'] : [])
    .join('');
};

/**
 * 从一次登录提交的口令派生「字典特征」三字段：命中词干表与否 + 长度档 + 字符集类。
 * 返回值里没有口令、没有口令的哈希，也没有长度原值——只有布尔与档位（判据见 tests/constants/credentialShape）。
 * @param {unknown} password 口令原文（只在内存里经过本函数）
 * @returns {{credentialStemHits: (0|1), lengthBucket: string, charsetClass: string}|null} 空口令返回 null
 */
const credentialShapeOf = (password) => {
  const text = asText(password);
  if (text === '') return null;
  return Object.freeze({
    credentialStemHits: isBreachedPassword(text) ? 1 : 0,
    lengthBucket: lengthBucketOf(text),
    charsetClass: charsetClassOf(text),
  });
};

module.exports = {
  CHARSET_FLAGS,
  CREDENTIAL_SHAPE_FIELDS,
  LENGTH_BOUNDARIES,
  LENGTH_BUCKETS,
  charsetClassOf,
  credentialShapeOf,
  lengthBucketOf,
};
