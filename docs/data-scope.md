# 数据范围判定（dataScope）说明

本文件承接 `src/middleware/dataScope.js` 部分内联注释的论证（注释密度棘轮按文件封顶，论证移此；行内不变量注释仍在原处）。

## 为什么从 rbac.js 抽出

`services/auditScopeFilter` 只需要「算范围 + 判范围不可用」三件套，若留在 rbac.js（其顶部还引用告警服务）就会形成 `securityAlert → auditScopeFilter → rbac → securityAlert` 的惰性环。本模块只依赖 User 模型与错误码，是叶子节点；rbac.js 原样再导出这三个名字，既有调用方与测试口径不变。

## 内置 GUEST（level 1）为什么归 all 档

内置 GUEST 是**全量业务数据只读**：它的「只读」由权限码约束（rolePermissionMap 只给 device/alarm/inspection/report 的 read），数据范围本身没有「只读」这一档。若按 level 归入 none，访客登录后列表/报表/详情一律 403——与 README 的「访客：设备/报警/巡检/报表只读」直接矛盾（且公开注册默认角色就是 GUEST）。因此按角色 code 单独放行到 all，其余 level<4 的自定义角色仍是 none（新增低级别角色不得因本例外获得全量可见性）。
