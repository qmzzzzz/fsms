/**
 * 数据范围字段声明（单一事实来源）
 *
 * 背景（P2-20）：同一资源的「属主字段」在不同代码路径各写一遍，口径已经漂移：
 *   设备 self 范围：列表用 maintenanceRecord.operator，报表/导出/统计用 createdBy
 * 后果是「维护过但非本人创建」的设备出现在列表却不在导出，
 * 「本人创建从未维护」反之——统计数字与可见清单永久对不上，
 * 且导出口径比列表宽（越权面）。
 *
 * 这里把每个资源的 (ownerField, departmentField) 收敛成唯一声明，
 * 所有调用方引用同一常量，杜绝新增路径时再抄一份不同的字段名。
 *
 * ownerField 支持数组：设备的「属主」在业务上确实是两层含义——
 * 创建者与维护操作者都应看到自己相关的设备。用数组表达「任一命中即在范围内」，
 * 而不是二选一（选任何一个都会让另一类人丢失本该可见的数据）。
 */

const DATA_SCOPE_FIELDS = {
  device: {
    // createdBy：建档人；maintenanceRecord.operator：维护过该设备的人（数组字段）
    ownerField: ['createdBy', 'maintenanceRecord.operator'],
    departmentField: 'location.building',
  },
  alarm: {
    ownerField: 'reporter.userId',
    departmentField: 'location.building',
  },
  inspection: {
    ownerField: 'assignedTo',
    departmentField: 'locations.building',
  },
  user: {
    ownerField: 'createdBy',
    departmentField: 'department',
  },
};

module.exports = { DATA_SCOPE_FIELDS };
