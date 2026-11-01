/** 取证清单的写失败重试队列（B-3）：清单写在落库之后，写失败不丢记录，但那一批会永久不在清单内（复核显示为缺失批次），一次磁盘抖动换一个永久空洞。 队列必须有界——磁盘满了还一直堆会撑爆内存，比丢一批清单严重得多；超限丢弃必须计数（丢了不说=静默降级）。 重放必须保序：队列头失败就整体停下，乱序补写会让 chainHash 对不上，等于把「补写成功」变成「补出一堆假断裂」。 */
const MAX_PENDING = 500;

const state = { pending: [], retried: 0, droppedPending: 0 };

/** 入队。超限丢**最旧的**：最新批次更接近当前时间，复核时更可能需要它 */
function enqueue(batch) {
  if (state.pending.length >= MAX_PENDING) {
    state.pending.shift();
    state.droppedPending += 1;
  }
  state.pending.push(batch);
}

/** 尽力重放。writeFn(batch) 成功返回、失败抛错。 头一个失败就 return（保序优先于重放数量）。 / */
async function drain(writeFn) {
  while (state.pending.length) {
    try {
      await writeFn(state.pending[0]);
    } catch (e) {
      return;
    }
    state.pending.shift();
    state.retried += 1;
  }
}

const getRetryStats = () => ({
  pending: state.pending.length,
  retried: state.retried,
  droppedPending: state.droppedPending,
});

const resetRetryState = () => {
  state.pending.length = 0;
  state.retried = 0;
  state.droppedPending = 0;
};

module.exports = { MAX_PENDING, enqueue, drain, getRetryStats, resetRetryState };
