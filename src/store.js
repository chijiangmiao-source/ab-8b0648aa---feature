'use strict';

/**
 * 持久化存储：单写者串行队列 + 原子文件提交。
 *
 * 每次 commit(mutator)：
 *  1. 在串行队列中执行 mutator（纯函数：state → {state, result}）；
 *  2. 若返回了新状态，则一次性写入临时文件、fsync、rename 替换、
 *     fsync 目录 —— 这是一次“持久化提交”，要么完整生效要么不生效；
 *  3. 只有落盘成功后才更新内存状态。
 *
 * 因此“收集到足够签名 → 激活候选 → 取代竞争候选 → 链头前进”
 * 永远落在同一次持久化提交里；并发的补签/重传在队列中串行收敛，
 * 不会产生第二个活动检查点。
 */

const fs = require('node:fs');
const path = require('node:path');

const { sweepExpirations } = require('./rotation');

const STATE_VERSION = 1;

function initialState() {
  return { version: STATE_VERSION, domains: {} };
}

/**
 * 兼容旧状态：截止时刻为后加的可选字段，历史候选可能没有
 * expiresAt/expiredAt；补成 null 后即与新模型一致（版本号不变，
 * 字段是附加的可选项）。已激活/待签/已过期状态本身一直落盘，
 * 重启后可直接从历史区分。
 */
function normalizeState(parsed) {
  let changed = false;
  for (const domain of Object.values(parsed.domains)) {
    for (const rotation of Object.values(domain.rotations)) {
      if (!('expiresAt' in rotation)) {
        rotation.expiresAt = null;
        changed = true;
      }
      if (!('expiredAt' in rotation)) {
        rotation.expiredAt = null;
        changed = true;
      }
    }
  }
  return changed;
}

class Store {
  constructor(file) {
    this.file = file;
    this.state = null;
    this._queue = Promise.resolve();
  }

  /** 启动时加载；状态文件不存在则初始化空状态并落盘。 */
  load() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    if (fs.existsSync(this.file)) {
      const raw = fs.readFileSync(this.file, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.version !== STATE_VERSION || typeof parsed.domains !== 'object' || parsed.domains === null) {
        throw new Error(`状态文件损坏或版本不受支持：${this.file}`);
      }
      if (normalizeState(parsed)) this._persist(parsed);
      this.state = parsed;
    } else {
      this.state = initialState();
      this._persist(this.state);
    }
    return this.state;
  }

  /**
   * 串行执行一次状态迁移。mutator 抛错时通常不产生持久化变更；
   * 但若拒因携带了 persistState（例如拒绝补签前已把到期候选固定为
   * 已过期），固化结果仍在这同一个串行槽位中原子落盘，随后再向
   * 调用方抛出拒因 —— “固定过期 + 拒绝”不会拆成两次提交。
   * mutator 返回原状态引用时跳过落盘（纯拒绝路径不改变链头）。
   */
  commit(mutator) {
    const run = this._queue.then(() => {
      try {
        const outcome = mutator(this.state);
        if (!outcome || typeof outcome !== 'object' || !('state' in outcome)) {
          throw new Error('mutator 必须返回 { state, result }');
        }
        const { state, result } = outcome;
        if (state !== this.state) {
          this._persist(state);
          this.state = state;
        }
        return result;
      } catch (err) {
        if (err && err.persistState && err.persistState !== this.state) {
          this._persist(err.persistState);
          this.state = err.persistState;
        }
        throw err;
      }
    });
    // 队列本身不因单次失败而中断。
    this._queue = run.catch(() => {});
    return run;
  }

  /**
   * 读取路径上的截止裁决：与补签共用同一条串行队列，把已过截止
   * 时刻的待签候选固化为“已过期”。没有候选到期时返回原状态、
   * 不落盘；到期则在同一次原子提交中持久化。这样“截止后首次
   * 补签或读取”都能稳定固定结论，且与并发补签只可能收敛为一个
   * 结果（激活或过期），不会竞争出两个结论。
   */
  settle(now) {
    const run = this._queue.then(() => {
      const next = sweepExpirations(this.state, now);
      if (next !== this.state) {
        this._persist(next);
        this.state = next;
      }
      return this.state;
    });
    this._queue = run.catch(() => {});
    return run;
  }

  /** 原子提交：写临时文件 → fsync → rename → fsync 目录。 */
  _persist(state) {
    const tmp = `${this.file}.tmp`;
    const fd = fs.openSync(tmp, 'w');
    try {
      fs.writeSync(fd, JSON.stringify(state, null, 2));
      fs.writeSync(fd, '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.file);
    const dirFd = fs.openSync(path.dirname(this.file), 'r');
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  }
}

module.exports = { Store, initialState, STATE_VERSION };
