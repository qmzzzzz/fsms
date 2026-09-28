/**
 * 连接失败日志的凭据脱敏（src/config/database.js）
 *
 * 背景：`MONGODB_URI` 按本仓约定内含数据库口令（config/secrets.js 把它列入
 * FILE_BACKED_SECRETS，理由原文就是"内含数据库口令"）。而 mongoose 8.24.1 解析连接串
 * 用的是它**内嵌**的那一份 mongodb-connection-string-url@3.0.2，该版本在
 * 「带 userinfo、缺 host」的形态下会把整条 URI 原样拼进 MongoParseError.message，
 * 于是 `connectDB` 的 catch 打印 `error.message` 时就把明文口令写进了日志文件。
 *
 * 本套件钉住两件事，缺一不可：
 *   ① 脱敏函数把 userinfo 换成 `***:***`，同时保留 scheme/host/port/db；
 *   ② **上游确实会回显**（见最后一条用例）——若它转红，说明 mongoose 或其内嵌解析包
 *      升级后改了行为，届时应重新评估脱敏是否仍必要，但**不要**据此直接删掉脱敏：
 *      顶层 mongodb 与 mongoose 内嵌的是两份不同版本的解析器，行为并不一致。
 *
 * 注意 ② 必须走 `mongoose.connect`：顶层 mongodb@7.5.0 自带的同包（7.0.2）对同一输入
 * 只抛常量串 `Protocol and host list are required in the uri`、不回显 URI，
 * 用 `new MongoClient(uri)` 验证会得出「不泄漏」的**反向结论**。
 */
const mongoose = require('mongoose');

const connectDB = require('../../config/database');

const { redactUriCredentials } = connectDB.__test;

const ECHO_PREFIX = 'Protocol and host list are required in ';

describe('config/database 连接失败日志的凭据脱敏', () => {
  test('mongoose 实际回显形态：userinfo 被替换，host/db 保留', () => {
    const raw = `${ECHO_PREFIX}"mongodb://appuser:s3cret@/fsms"`;
    expect(redactUriCredentials(raw)).toBe(`${ECHO_PREFIX}"mongodb://***:***@/fsms"`);
    expect(redactUriCredentials(raw)).not.toContain('s3cret');
  });

  test('带 host:port 的形态只脱 userinfo，其余逐字保留', () => {
    expect(redactUriCredentials('mongodb://appuser:s3cret@db.internal:27017/fsms')).toBe(
      'mongodb://***:***@db.internal:27017/fsms'
    );
  });

  test('mongodb+srv 串同样被脱敏（scheme 里的 + 不能让它漏出去）', () => {
    expect(redactUriCredentials('mongodb+srv://appuser:s3cret@cluster0.example.net/fsms')).toBe(
      'mongodb+srv://***:***@cluster0.example.net/fsms'
    );
  });

  test('口令含未转义 / 的形态也被脱敏', () => {
    expect(redactUriCredentials('Invalid connection string "mongodb://appuser:a/b@/fsms"')).toBe(
      'Invalid connection string "mongodb://***:***@/fsms"'
    );
  });

  test('不含凭据的连接串与普通错误文本是恒等变换（不误伤可读性）', () => {
    const plain = 'mongodb://localhost:27017/fire_safety_db';
    expect(redactUriCredentials(plain)).toBe(plain);
    const econn = 'connect ECONNREFUSED 127.0.0.1:27017';
    expect(redactUriCredentials(econn)).toBe(econn);
  });

  test('非字符串入参原样返回（undefined 不得被写成 "undefined"）', () => {
    expect(redactUriCredentials(undefined)).toBeUndefined();
    expect(redactUriCredentials(null)).toBeNull();
  });

  test('上游形状钉住：mongoose.connect 的报错确实回显整条 URI（含口令）', async () => {
    const uri = 'mongodb://appuser:s3cret@/fsms';
    const err = await mongoose
      .connect(uri, {
        serverSelectionTimeoutMS: 500,
        connectTimeoutMS: 500,
      })
      .then(
        () => null,
        (e) => e
      );

    expect(err).toBeTruthy();
    expect(err.constructor.name).toBe('MongoParseError');
    // ← 这条断言就是本用例存在的理由：报错文本里带着整条 URI
    expect(err.message).toContain(uri);
    // 而这正是脱敏要消掉的东西
    expect(redactUriCredentials(err.message)).not.toContain('s3cret');
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });
});
