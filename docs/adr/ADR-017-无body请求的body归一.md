# ADR-017 无 body 请求的 body 归一（Express 5 与校验链的静默失效）

- 状态：已采纳（2026-11-01）
- 相关：ADR-011（注释治理）、`src/middleware/security/index.js` 的 `normalizeBody`、
  `src/tests/middleware/bodyNormalization.test.js`

## 背景

Express 5.3 与 4.x 有一处行为差异：**POST 不带 `Content-Type`（或不带 body）时 `req.body` 是
`undefined`**，而 4.x 恒为 `{}`。差异本身无害，有害的是它的下游组合：

1. 路由里的 `body('password').if((value, { req }) => !req.body.encPassword)` 这类谓词，在
   `req.body` 为 `undefined` 时抛 `TypeError`；
2. express-validator 7.x 对**谓词抛错**的处置是把整条链当作"跳过"——`validationResult(req)`
   里 0 条错误、错误中间件不触发、响应码由控制器决定；
3. 于是"必填字段校验"整条失效，请求直达控制器里的 `req.body.username`（或
   `const { currentPassword } = req.body`）⇒ `TypeError` ⇒ **500**（本该是 400）。

本仓库实测（`work/lead/probe-body5.cjs`，用**生产真实的** `reauthCredentialValidation`）：

```
无归一: 500 {"m":"Cannot destructure property 'currentPassword' of 'req.body' as it is undefined."}
有归一: 200 {"got":null}
```

可达性：`middleware/protocolCompliance.js` 的 Content-Type 闸只在有 body 时生效（该行为由
`tests/middleware/protocolCompliance.test.js` 明确断言为有意设计），因此无 body 的 POST
能一路走到路由校验链。仓库内已有一处同因的局部兜底
（`requireReAuthentication` 对 undefined body 返回 403），但它只覆盖那一个中间件，
校验链与控制器没有全局兜底。

## 决策

在 `applyPostBodySecurity` 的**最前面**挂一个 `normalizeBody`：`if (!req.body) req.body = {}`。
位置选在这里的理由：它紧随 `express.json()/urlencoded()` 之后，归一一次后，
`sanitizeMongo/preventHPP`、全部校验链、全部控制器看到的是同一份 `{}`，与 Express 4 对齐。

## 备选与取舍

- **在各个 `.if()` 谓词里加空值守卫**：改动面散在十几处路由，且新增谓词仍会重复犯错；
  一次性归一只需一处，且"新写的谓词不会再踩"是可验证的性质。否决。
- **把 `.if()` 换成 `.optional()`**：两者语义不同（`.if()` 表达"条件特征"，`.optional()` 表达
  "可缺省"）；为绕开一个框架歧义去改业务判据，是把缺陷藏进语义。否决。
- **只在控制器里兜 `req.body || {}`**：控制器数量远多于中间件，且校验链仍然静默失效——
  等于把"必填校验不生效"这条长期隐患留下。否决。
- **成本**：无 body 的请求现在会走到校验链并得到 400（此前是 500）。这是修复本身，不是副作用。

## 后果与防线

- 反例与正向对照都在 `tests/middleware/bodyNormalization.test.js`：其中一条**故意不挂**
  `applyPostBodySecurity`，断言同一请求以 500 收场——去掉守卫时该文件必然变红，
  防止这组用例退化成恒真。
- `tests/middleware/securityApplyAndCategoryGuard.test.js` 的挂载计数从 9 改为 10，
  新增的那一个就是本决策的挂载点（该用例钉的就是"挂载面不许悄悄变"）。
