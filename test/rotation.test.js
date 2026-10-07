'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const rotation = require('../src/rotation');
const { Store, migrate, STATE_VERSION } = require('../src/store');

const NOW = '2026-10-06T00:00:00.000Z';

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { publicKey: pub, privateKey };
}

function sign(privateKey, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('hex');
}

function freshState() {
  return { version: STATE_VERSION, domains: {} };
}

function makeDomain(state, keys, threshold) {
  const { state: s2, result } = rotation.createDomain(
    state,
    { name: '测试域', publicKeys: keys.map((k) => k.publicKey), threshold },
    NOW,
  );
  return { state: s2, domain: result };
}

test('密钥集校验：排序、去重、数量与门限边界', () => {
  const a = 'a'.repeat(64);
  const b = 'B'.repeat(64); // 大写应归一化
  const c = 'c'.repeat(64);
  const { keys, threshold } = rotation.validateKeySet([c, a, b], 2);
  assert.deepEqual(keys, ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]);
  assert.equal(threshold, 2);

  assert.throws(() => rotation.validateKeySet([a, a], 1), /重复/);
  assert.throws(() => rotation.validateKeySet([a], 1), (e) => e.code === 'invalid_key_set');
  assert.throws(() => rotation.validateKeySet([a, b, c, 'd'.repeat(64), 'e'.repeat(64), 'f'.repeat(64)], 1), /2–5/);
  assert.throws(() => rotation.validateKeySet([a, 'zz'.repeat(32)], 1), /十六进制/);
  assert.throws(() => rotation.validateKeySet([a, b], 0), (e) => e.code === 'invalid_threshold');
  assert.throws(() => rotation.validateKeySet([a, b], 3), (e) => e.code === 'invalid_threshold');
  assert.throws(() => rotation.validateKeySet([a, b], 1.5), (e) => e.code === 'invalid_threshold');
});

test('检查点摘要与授权消息：规范化、确定性、与输入顺序无关', () => {
  const base = {
    domainId: 'dom-1',
    rotationId: 'rot-1',
    parentDigest: '0'.repeat(64),
    generation: 1,
    threshold: 2,
    keys: rotation.sortKeys(['b'.repeat(64), 'a'.repeat(64)]),
  };
  const same = { ...base, keys: rotation.sortKeys(['a'.repeat(64), 'b'.repeat(64)]) };
  assert.equal(rotation.checkpointDigest(base), rotation.checkpointDigest(same));
  assert.match(rotation.checkpointDigest(base), /^[0-9a-f]{64}$/);

  const message = rotation.authorizationMessage(base);
  assert.ok(message.includes('parent=' + '0'.repeat(64)));
  assert.ok(message.includes('keys=' + 'a'.repeat(64) + ',' + 'b'.repeat(64)));
  // 任一字段变化都会改变待签消息（篡改载荷必然验签失败）。
  assert.notEqual(rotation.authorizationMessage({ ...base, threshold: 3 }), message);
  assert.notEqual(rotation.authorizationMessage({ ...base, rotationId: 'rot-2' }), message);
  assert.notEqual(rotation.authorizationMessage({ ...base, parentDigest: '1'.repeat(64) }), message);
});

test('创建设备域：创世检查点立即激活并成为链头', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  assert.equal(domain.generation, 0);
  assert.equal(domain.headDigest, Object.keys(domain.checkpoints)[0]);
  const genesis = domain.checkpoints[domain.headDigest];
  assert.equal(genesis.status, 'activated');
  assert.equal(genesis.parentDigest, '0'.repeat(64));
  assert.deepEqual(genesis.keys, rotation.sortKeys(keys.map((k) => k.publicKey)));
  assert.ok(state.domains[domain.id]);
});

test('创建轮换：错误父摘要被拒且不改变状态；同标识幂等；冲突载荷被拒', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  const next = [genKey(), genKey()];

  assert.throws(
    () => rotation.createRotation(state, domain.id, { rotationId: 'r1', parentDigest: 'f'.repeat(64), publicKeys: next.map((k) => k.publicKey), threshold: 2 }, NOW),
    (e) => e.code === 'wrong_parent_digest',
  );

  const input = { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 };
  const first = rotation.createRotation(state, domain.id, input, NOW);
  assert.equal(first.result.created, true);
  assert.equal(first.result.rotation.generation, 1);
  assert.equal(first.result.rotation.parentDigest, domain.headDigest);

  const again = rotation.createRotation(first.state, domain.id, input, NOW + 'x');
  assert.equal(again.result.created, false);
  assert.equal(again.state, first.state, '幂等创建不应改变状态');

  assert.throws(
    () => rotation.createRotation(first.state, domain.id, { ...input, threshold: 1 }, NOW),
    (e) => e.code === 'conflicting_rotation',
  );
});

test('签名提交：非成员、篡改载荷、重复签名均被拒且不改变状态', () => {
  const members = [genKey(), genKey()];
  const outsider = genKey();
  const { state, domain } = makeDomain(freshState(), members, 2);
  const next = [genKey(), genKey()];
  const created = rotation.createRotation(
    state,
    domain.id,
    { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 },
    NOW,
  );
  const rot = created.result.rotation;
  const message = rotation.authorizationMessage(rot);

  // 非父密钥成员
  const notMember = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: outsider.publicKey, signature: sign(outsider.privateKey, message) }],
    NOW,
  );
  assert.equal(notMember.result.results[0].code, 'not_parent_member');
  assert.equal(notMember.state, created.state);

  // 篡改载荷：签的是别的消息
  const tampered = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message + '\nextra=1') }],
    NOW,
  );
  assert.equal(tampered.result.results[0].code, 'invalid_signature');
  assert.equal(tampered.state, created.state);

  // 合法签名被接受
  const one = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  );
  assert.equal(one.result.results[0].status, 'accepted');
  assert.equal(one.result.activated, false);
  assert.equal(one.result.signers, 1);

  // 重传同一签名 → 重复拒因，状态不变
  const dup = rotation.submitSignatures(
    one.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  );
  assert.equal(dup.result.results[0].code, 'duplicate_signature');
  assert.equal(dup.state, one.state);

  // 同批内重复也只计一次
  const sameBatch = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [
      { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) },
      { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) },
    ],
    NOW,
  );
  assert.equal(sameBatch.result.results[0].status, 'accepted');
  assert.equal(sameBatch.result.results[1].code, 'duplicate_signature');
  assert.equal(sameBatch.result.signers, 1);
});

test('达到父门限即激活：链头前进、证据完整、竞争候选被取代、迟到签名被拒', () => {
  const members = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), members, 2);
  const nextA = [genKey(), genKey()];
  const nextB = [genKey(), genKey(), genKey()];

  const s1 = rotation.createRotation(state, domain.id, { rotationId: 'win', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW).state;
  const s2 = rotation.createRotation(s1, domain.id, { rotationId: 'lose', parentDigest: domain.headDigest, publicKeys: nextB.map((k) => k.publicKey), threshold: 2 }, NOW).state;

  const rotWin = s2.domains[domain.id].rotations.win;
  const msgWin = rotation.authorizationMessage(rotWin);
  const rotLose = s2.domains[domain.id].rotations.lose;
  const msgLose = rotation.authorizationMessage(rotLose);

  // 两个候选各收一票（竞争提交进行中）
  const s3 = rotation.submitSignatures(s2, domain.id, 'win', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgWin) }], NOW).state;
  const s4 = rotation.submitSignatures(s3, domain.id, 'lose', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgLose) }], NOW).state;

  // win 达到门限 → 激活；lose 在同一迁移中被取代
  const done = rotation.submitSignatures(s4, domain.id, 'win', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgWin) }], NOW);
  assert.equal(done.result.activated, true);
  const after = done.state.domains[domain.id];
  assert.equal(after.headDigest, rotWin.digest);
  assert.equal(after.generation, 1);
  assert.deepEqual(after.keys, rotWin.keys);
  const headCp = after.checkpoints[after.headDigest];
  assert.equal(headCp.evidence.length, 2);
  assert.deepEqual(headCp.evidence.map((e) => e.publicKey).sort(), members.map((m) => m.publicKey).sort());
  assert.equal(after.rotations.lose.status, 'superseded');
  assert.match(after.rotations.lose.rejectedReason, /取代/);

  // 迟到的签名（激活后补签）被拒，链头不变
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'win', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgWin) }], NOW),
    (e) => e.code === 'rotation_already_activated',
  );
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'lose', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgLose) }], NOW),
    (e) => e.code === 'rotation_superseded',
  );
  assert.equal(done.state.domains[domain.id].headDigest, rotWin.digest);

  // 激活后用旧父摘要创建竞争候选 → 错误父摘要
  assert.throws(
    () => rotation.createRotation(done.state, domain.id, { rotationId: 'late', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW),
    (e) => e.code === 'wrong_parent_digest',
  );
});

test('持久化：提交后重载状态一致；并发补签只收敛为一个活动检查点', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-store-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '并发域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const next = [genKey(), genKey()];
  await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 }, NOW));
  const rot = store.state.domains[domain.id].rotations.r1;
  const message = rotation.authorizationMessage(rot);

  // 并发提交两批签名 + 两批重传（乱序到达的补签与重传）
  const batch = (m) => [{ publicKey: m.publicKey, signature: sign(m.privateKey, message) }];
  const outcomes = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[0]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[1]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[0]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[1]), NOW)),
  ]);
  const fulfilled = outcomes.filter((o) => o.status === 'fulfilled').map((o) => o.value);
  const rejected = outcomes.filter((o) => o.status === 'rejected').map((o) => o.reason);
  assert.equal(fulfilled.filter((o) => o.activated).length, 1, '恰好一次提交触发激活');
  for (const late of rejected) assert.equal(late.code, 'rotation_already_activated', '激活后的重传应被拒');
  for (const f of fulfilled) {
    if (!f.activated) assert.ok(f.results.every((r) => r.status === 'rejected' || f.signers <= 2));
  }
  const finalDomain = store.state.domains[domain.id];
  assert.equal(finalDomain.headDigest, rot.digest);
  assert.equal(finalDomain.rotations.r1.signatures.length, 2, '重传被去重，仅两名签名者');
  assert.equal(finalDomain.checkpoints[rot.digest].evidence.length, 2);

  // 重载（模拟重启）后链头、检查点、证据完全一致
  const reloaded = new Store(file);
  reloaded.load();
  assert.deepEqual(reloaded.state, store.state);
  assert.ok(!fs.existsSync(`${file}.tmp`), '原子提交不残留临时文件');
});

test('持久化：竞争候选并发达标，磁盘上只有一个活动检查点', async () => {  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-race-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '竞争域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  for (const rid of ['race-1', 'race-2']) {
    const keys = [genKey(), genKey()];
    await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: rid, parentDigest: domain.headDigest, publicKeys: keys.map((k) => k.publicKey), threshold: 2 }, NOW));
  }
  const dom = () => store.state.domains[domain.id];
  const msg = (rid) => rotation.authorizationMessage(dom().rotations[rid]);
  const fullBatch = (rid) => members.map((m) => ({ publicKey: m.publicKey, signature: sign(m.privateKey, msg(rid)) }));

  const results = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'race-1', fullBatch('race-1'), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'race-2', fullBatch('race-2'), NOW)),
  ]);
  const fulfilled = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const rejected = results.filter((r) => r.status === 'rejected').map((r) => r.reason);
  assert.equal(fulfilled.filter((o) => o.activated).length, 1, '只有一个候选激活');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].code, 'rotation_superseded');

  const finalDomain = dom();
  const activated = Object.values(finalDomain.rotations).filter((r) => r.status === 'activated');
  assert.equal(activated.length, 1);
  assert.equal(finalDomain.headDigest, activated[0].digest);
  assert.equal(Object.values(finalDomain.checkpoints).filter((c) => c.generation === 1).length, 1, '同代次只有一个活动检查点');
});

test('截止时刻：创建校验、幂等兼容与剩余状态', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  const next = [genKey(), genKey()];
  const base = { rotationId: 'd1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 };

  // 非 UTC（缺 Z 后缀）/ 非字符串 / 过去时刻均被拒
  assert.throws(
    () => rotation.createRotation(state, domain.id, { ...base, rotationId: 'bad1', deadline: '2026-10-06T08:00:00' }, NOW),
    (e) => e.code === 'invalid_deadline',
  );
  assert.throws(
    () => rotation.createRotation(state, domain.id, { ...base, rotationId: 'bad2', deadline: '2026-10-05T00:00:00Z' }, NOW),
    (e) => e.code === 'invalid_deadline',
  );
  assert.throws(
    () => rotation.createRotation(state, domain.id, { ...base, rotationId: 'bad3', deadline: 1728000000000 }, NOW),
    (e) => e.code === 'invalid_deadline',
  );

  // 合法截止时刻被规范化为毫秒精度 ISO 字符串
  const created = rotation.createRotation(
    state, domain.id,
    { ...base, deadline: '2026-10-06T01:00:00.500Z' },
    NOW,
  );
  assert.equal(created.result.rotation.deadline, '2026-10-06T01:00:00.500Z');
  assert.equal(created.result.rotation.status, 'pending');
  assert.equal(created.result.rotation.expiredAt, null);

  // 同标识同载荷（含相同 deadline）幂等返回且不落盘
  const again = rotation.createRotation(created.state, domain.id, { ...base, deadline: '2026-10-06T01:00:00.500Z' }, NOW);
  assert.equal(again.result.created, false);
  assert.equal(again.state, created.state);

  // deadline 不同视为冲突载荷
  assert.throws(
    () => rotation.createRotation(created.state, domain.id, { ...base, deadline: '2026-10-06T02:00:00Z' }, NOW),
    (e) => e.code === 'conflicting_rotation',
  );

  // 截止时刻过后用相同载荷（含相同 deadline）幂等重放：返回既有候选，不抛“过去时刻”错误
  const replay = rotation.createRotation(
    created.state, domain.id,
    { ...base, deadline: '2026-10-06T01:00:00.500Z' },
    '2026-10-06T03:00:00.000Z',
  );
  assert.equal(replay.result.created, false);
  assert.equal(replay.state, created.state);

  // 无截止候选 deadline 为 null，且与有截止候选不冲突（不同 rid）
  const none = rotation.createRotation(
    created.state, domain.id,
    { ...base, rotationId: 'd2' },
    NOW,
  );
  assert.equal(none.result.rotation.deadline, null);

  const info = rotation.deadlineStatus(none.result.rotation, NOW);
  assert.equal(info, null);
  const open = rotation.deadlineStatus(created.result.rotation, '2026-10-06T00:59:59.999Z');
  assert.equal(open.windowOpen, true);
  assert.equal(open.remainingMs, 501);
  const closed = rotation.deadlineStatus(created.result.rotation, '2026-10-06T01:00:00.500Z');
  assert.equal(closed.windowOpen, false);
  assert.equal(closed.remainingMs, 0);
});

test('截止前达到父门限即激活；无截止候选保持长期有效', () => {
  const members = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), members, 2);
  const next = [genKey(), genKey()];
  const deadline = '2026-10-06T01:00:00.000Z';

  const withDeadline = rotation.createRotation(
    state, domain.id,
    { rotationId: 'win-before', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2, deadline },
    NOW,
  ).state;
  const rot = withDeadline.domains[domain.id].rotations['win-before'];
  const message = rotation.authorizationMessage(rot);

  // 截止前补齐门限 → 激活，链头前进
  const done = rotation.submitSignatures(
    withDeadline, domain.id, 'win-before',
    members.map((m) => ({ publicKey: m.publicKey, signature: sign(m.privateKey, message) })),
    '2026-10-06T00:59:59.000Z',
  );
  assert.equal(done.result.activated, true);
  assert.equal(done.state.domains[domain.id].headDigest, rot.digest);
  const cp = done.state.domains[domain.id].checkpoints[rot.digest];
  assert.equal(cp.status, 'activated');
  assert.equal(cp.evidence.length, 2);

  // 激活后的迟到补签仍得到既有的已激活拒因（而不是过期拒因）
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'win-before',
      [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
      '2026-10-07T00:00:00.000Z'),
    (e) => e.code === 'rotation_already_activated',
  );

  // 无截止候选在很久以后仍可正常补签激活（兼容既有行为）
  const head1 = done.state.domains[domain.id].headDigest;
  const next2 = [genKey(), genKey()];
  const s2 = rotation.createRotation(
    done.state, domain.id,
    { rotationId: 'no-window', parentDigest: head1, publicKeys: next2.map((k) => k.publicKey), threshold: 2 },
    NOW,
  ).state;
  const rot2 = s2.domains[domain.id].rotations['no-window'];
  const msg2 = rotation.authorizationMessage(rot2);
  // 父检查点密钥集是上一轮激活的 next，而非创世成员
  const later = rotation.submitSignatures(
    s2, domain.id, 'no-window',
    next.map((m) => ({ publicKey: m.publicKey, signature: sign(m.privateKey, msg2) })),
    '2030-01-01T00:00:00.000Z',
  );
  assert.equal(later.result.activated, true);
  assert.equal(later.state.domains[domain.id].headDigest, rot2.digest);
});

test('截止后首次补签固定为已过期：稳定拒因、链头/证据/竞争候选均不改写', () => {
  const members = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), members, 2);
  const nextA = [genKey(), genKey()];
  const nextB = [genKey(), genKey()];
  const deadline = '2026-10-06T01:00:00.000Z';

  const s1 = rotation.createRotation(
    state, domain.id,
    { rotationId: 'exp', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2, deadline },
    NOW,
  ).state;
  const s2 = rotation.createRotation(
    s1, domain.id,
    { rotationId: 'rival', parentDigest: domain.headDigest, publicKeys: nextB.map((k) => k.publicKey), threshold: 2 },
    NOW,
  ).state;
  const rotExp = s2.domains[domain.id].rotations.exp;
  const msgExp = rotation.authorizationMessage(rotExp);
  const rotRival = s2.domains[domain.id].rotations.rival;
  const msgRival = rotation.authorizationMessage(rotRival);

  // 截止前仅一份签名（1/2，未达门限）
  const s3 = rotation.submitSignatures(
    s2, domain.id, 'exp',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgExp) }],
    '2026-10-06T00:30:00.000Z',
  ).state;
  assert.equal(s3.domains[domain.id].rotations.exp.signatures.length, 1);
  assert.equal(s3.domains[domain.id].headDigest, domain.headDigest);

  // 截止后首次补签：迁移固定过期并返回 rejection
  const fixed = rotation.submitSignatures(
    s3, domain.id, 'exp',
    [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgExp) }],
    '2026-10-06T01:00:00.000Z',
  );
  assert.ok(fixed.result.rejected, '截止后首次补签应返回 rejection');
  assert.equal(fixed.result.rejection.code, 'rotation_expired');
  const after = fixed.state.domains[domain.id];
  assert.equal(after.rotations.exp.status, 'expired');
  assert.equal(after.rotations.exp.expiredAt, '2026-10-06T01:00:00.000Z');
  assert.equal(after.rotations.exp.signatures.length, 1, '本批签名不得在过期固定时落盘');
  assert.equal(after.headDigest, domain.headDigest, '过期固定不得推进链头');
  assert.equal(Object.keys(after.checkpoints).length, 1, '过期固定不得产生检查点');
  assert.equal(after.rotations.rival.status, 'pending', '竞争候选不得被过期固定改写');

  // 此后的任何补签（含本可凑齐门限的迟到签名）得到稳定拒因，状态不再变化
  let late;
  try {
    rotation.submitSignatures(
      fixed.state, domain.id, 'exp',
      [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgExp) }],
      '2026-10-06T02:00:00.000Z',
    );
  } catch (e) {
    late = e;
  }
  assert.ok(late, '过期固定后的补签必须抛出拒因');
  assert.equal(late.code, 'rotation_expired');
  const finalDomain = fixed.state.domains[domain.id];
  assert.equal(finalDomain.headDigest, domain.headDigest);
  assert.equal(finalDomain.rotations.exp.signatures.length, 1);
  assert.equal(finalDomain.rotations.exp.status, 'expired');

  // 竞争候选仍可在同一父摘要上正常收集签名（未被改写）
  const rivalOne = rotation.submitSignatures(
    fixed.state, domain.id, 'rival',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgRival) }],
    '2026-10-06T03:00:00.000Z',
  );
  assert.equal(rivalOne.result.results[0].status, 'accepted');
  assert.equal(rivalOne.state.domains[domain.id].rotations.rival.status, 'pending');
});

test('读取驱动的过期固定：截止后首次读取固定全部过期候选，且幂等', () => {
  const members = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), members, 2);
  const next = [genKey(), genKey()];
  const s1 = rotation.createRotation(
    state, domain.id,
    { rotationId: 'r-exp', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2, deadline: '2026-10-06T01:00:00.000Z' },
    NOW,
  ).state;
  const s2 = rotation.createRotation(
    s1, domain.id,
    { rotationId: 'r-open', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey).reverse(), threshold: 2, deadline: '2026-10-07T01:00:00.000Z' },
    NOW,
  ).state;
  const s3 = rotation.createRotation(
    s2, domain.id,
    { rotationId: 'r-never', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey).sort(), threshold: 2 },
    NOW,
  ).state;

  // 截止前读取：无固定，返回原状态引用（不落盘）
  assert.equal(rotation.sweepExpiredRotations(s3, domain.id, '2026-10-06T00:59:59.999Z'), s3);

  // 截止后首次读取：只固定已过期候选
  const swept = rotation.sweepExpiredRotations(s3, domain.id, '2026-10-06T01:30:00.000Z');
  assert.notEqual(swept, s3);
  const d = swept.domains[domain.id];
  assert.equal(d.rotations['r-exp'].status, 'expired');
  assert.equal(d.rotations['r-exp'].expiredAt, '2026-10-06T01:30:00.000Z');
  assert.equal(d.rotations['r-open'].status, 'pending');
  assert.equal(d.rotations['r-never'].status, 'pending');
  assert.equal(d.headDigest, domain.headDigest);

  // 再次读取：幂等（无新固定，返回原引用）
  assert.equal(rotation.sweepExpiredRotations(swept, domain.id, '2026-10-06T02:00:00.000Z'), swept);
});

test('并发末秒补签与过期补签：串行队列下只有一个结论', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-deadline-race-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '末秒域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const next = [genKey(), genKey()];
  await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: 'lastsec', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2, deadline: '2026-10-06T01:00:00.000Z' }, NOW));
  const rot = store.state.domains[domain.id].rotations.lastsec;
  const message = rotation.authorizationMessage(rot);

  // 先持有一份截止前的签名
  await store.commit((s) => rotation.submitSignatures(s, domain.id, 'lastsec',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    '2026-10-06T00:59:58.000Z'));

  // 并发：末秒（截止前）补第二票 vs 截止后补第二票。两者使用同一 now 仅由队列顺序决定先后不可假设，
  // 因此直接验证：无论顺序，最终状态只有一个结论——激活或过期，绝不两者并存。
  const outcomes = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'lastsec',
      [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, message) }],
      '2026-10-06T00:59:59.999Z')),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'lastsec',
      [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, message) }],
      '2026-10-06T01:00:00.000Z')),
  ]);
  const finalDomain = store.state.domains[domain.id];
  const finalStatus = finalDomain.rotations.lastsec.status;
  assert.ok(['activated', 'expired'].includes(finalStatus), `最终状态只能是激活或过期，实际 ${finalStatus}`);

  if (finalStatus === 'activated') {
    // 末秒补签先排空：恰好一个激活结果，截止后补签得到 rotation_already_activated
    assert.equal(finalDomain.headDigest, rot.digest);
    const fulfilled = outcomes.filter((o) => o.status === 'fulfilled').map((o) => o.value);
    assert.equal(fulfilled.filter((o) => o.activated).length, 1);
    const rejected = outcomes.filter((o) => o.status === 'rejected').map((o) => o.reason);
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].code, 'rotation_already_activated');
  } else {
    // 截止后补签先排空：候选固定过期，两次提交都不推进链头
    assert.equal(finalDomain.headDigest, domain.headDigest);
    assert.equal(finalDomain.rotations.lastsec.signatures.length, 1);
    for (const o of outcomes) {
      // 首次（固定）迁移由 result.rejection 携带；后续为抛出的稳定拒因
      const reason = o.status === 'rejected' ? o.reason : o.value && o.value.rejection;
      assert.equal(reason.code, 'rotation_expired');
    }
  }

  // 重启后仍能区分已激活/待签/已过期
  const reloaded = new Store(path.join(dir, 'state.json'));
  reloaded.load();
  const rd = reloaded.state.domains[domain.id];
  assert.equal(rd.rotations.lastsec.status, finalStatus);
  assert.deepEqual(rd.headDigest, finalDomain.headDigest);
});

test('持久化迁移 v1→v2：旧候选补齐 deadline=null 并保持既有补签激活行为', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-migrate-'));
  const file = path.join(dir, 'state.json');
  const members = [genKey(), genKey()];
  const next = [genKey(), genKey()];

  // 手工构造一个 v1 状态（无 deadline 字段的待签候选）
  const legacy = rotation.createDomain(
    { version: 1, domains: {} },
    { name: '旧版域', publicKeys: members.map((m) => m.publicKey), threshold: 2 },
    NOW,
  );
  const legacyDomain = legacy.result;
  const withRot = rotation.createRotation(
    legacy.state, legacyDomain.id,
    { rotationId: 'legacy-rot', parentDigest: legacyDomain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 },
    NOW,
  );
  const legacyState = { ...withRot.state, version: 1 };
  // 去掉 rotation 上的 deadline/expiredAt 字段模拟旧版落盘格式
  const rotEntries = Object.entries(legacyState.domains[legacyDomain.id].rotations);
  const oldRotations = Object.fromEntries(
    rotEntries.map(([rid, r]) => {
      const { deadline, expiredAt, ...rest } = r;
      return [rid, rest];
    }),
  );
  legacyState.domains[legacyDomain.id].rotations = oldRotations;
  fs.writeFileSync(file, JSON.stringify(legacyState));

  const migrated = migrate(JSON.parse(fs.readFileSync(file, 'utf8')));
  assert.equal(migrated.version, 2);
  assert.equal(migrated.domains[legacyDomain.id].rotations['legacy-rot'].deadline, null);
  assert.equal(migrated.domains[legacyDomain.id].rotations['legacy-rot'].expiredAt, null);

  // 经 Store 加载（迁移落盘）后旧候选仍可补签激活
  const store = new Store(file);
  store.load();
  const rot = store.state.domains[legacyDomain.id].rotations['legacy-rot'];
  const message = rotation.authorizationMessage(rot);
  const done = await store.commit((s) => rotation.submitSignatures(s, legacyDomain.id, 'legacy-rot',
    members.map((m) => ({ publicKey: m.publicKey, signature: sign(m.privateKey, message) })), NOW));
  assert.equal(done.activated, true);
  assert.equal(store.state.domains[legacyDomain.id].headDigest, rot.digest);

  // 磁盘版本已升级到 v2
  const onDisk = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(onDisk.version, 2);
});
