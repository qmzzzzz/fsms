'use strict';

const { maskTarget } = require('../../../scripts/alert-delivery-probe');

describe('alert-delivery-probe：目标 URL 落盘前掩码', () => {
  test('查询串被掩掉（access_token 常在处），host/path 保留', () => {
    expect(
      maskTarget('https://open.feishu.cn/open-apis/bot/v2/hook/abc-123?access_token=SECRET&x=1')
    ).toBe('https://open.feishu.cn/open-apis/bot/v2/hook/abc-123?<masked>');
  });

  test('无查询串与片段的 URL 原样返回，不添加占位符', () => {
    expect(maskTarget('http://127.0.0.1:9093/api/v2/alerts')).toBe(
      'http://127.0.0.1:9093/api/v2/alerts'
    );
  });

  test('片段同样掩码；非法 URL 给出稳定占位符（不抛错、不回显原文）', () => {
    expect(maskTarget('https://a.b/c#frag')).toBe('https://a.b/c#<masked>');
    expect(maskTarget('not a url')).toBe('<url-unparseable>');
  });
});
