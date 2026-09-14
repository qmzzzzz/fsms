/**
 * migrate-mongo 配置（O-9：数据库迁移框架）
 *
 * 连接串与运行时同一口径：优先 MONGODB_URI（支持 *_FILE 注入），
 * 缺省指向本机默认库。执行任何迁移命令前会先水合 secrets 文件，
 * 与 scripts/ 下各维护脚本的引导方式一致。
 *
 * 常用命令（见 package.json）：
 *   npm run migrate:create -- <名称>   新建迁移文件（生成时间戳前缀）
 *   npm run migrate:status             查看已应用/待应用清单
 *   npm run migrate:up                 应用全部待执行迁移
 *   npm run migrate:down               回滚最近一条迁移（回退策略）
 */

require('dotenv').config();
require('./src/config/secrets').hydrateSecretsFromFiles();

const config = {
  mongodb: {
    url: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/fire_safety_db',
    options: {
      // 迁移为低频维护操作，显式超时避免挂起
      serverSelectionTimeoutMS: 5000,
    },
  },
  migrationsDir: 'migrations',
  changelogCollectionName: '_migrations',
  migrationFileExtension: '.js',
  // 以文件名（时间戳前缀）为迁移标识，保持与生成命令默认行为一致
  useFileHash: false,
  moduleSystem: 'commonjs',
};

module.exports = config;
