'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const rotation = require('../src/rotation');
const { Store } = require('../src/store');

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
  return { version: 1, domains: {} };
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

test('持久化：竞争候选并发达标，磁盘上只有一个活动检查点', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-race-'));
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

function makeDeadlineDomain(state, members, threshold = 2) {
  const created = makeDomain(state, members, threshold);
  const next = [genKey(), genKey()];
  const nextKeys = next.map((k) => k.publicKey);
  return { ...created, nextKeys, makeRot: (s, rid, expiresAt, keys = nextKeys) =>
    rotation.createRotation(s, created.domain.id, { rotationId: rid, parentDigest: created.domain.headDigest, publicKeys: keys, threshold: 2, ...(expiresAt === undefined ? {} : { expiresAt }) }, NOW) };
}

test('截止时刻：创建时校验（缺省/空串不设截止；非法与过去时刻被拒）', () => {
  const members = [genKey(), genKey()];
  const { state, domain, makeRot } = makeDeadlineDomain(freshState(), members);
  const keys = [genKey(), genKey()].map((k) => k.publicKey);

  const none = makeRot(state, 'no-deadline', undefined);
  assert.equal(none.result.rotation.expiresAt, null);
  assert.equal(none.result.rotation.expiredAt, null);

  const empty = makeRot(state, 'empty-deadline', '');
  assert.equal(empty.result.rotation.expiresAt, null);

  const future = makeRot(state, 'future-deadline', '2026-10-06T01:00:00Z');
  assert.equal(future.result.rotation.expiresAt, '2026-10-06T01:00:00.000Z');
  // 截止时刻不进入候选摘要/规范文档（它是运营策略，不是签名载荷）
  const rotWithDeadline = future.result.rotation;
  assert.equal(
    rotation.checkpointDigest(rotWithDeadline),
    rotation.checkpointDigest({ ...rotWithDeadline, expiresAt: null }),
  );

  assert.throws(() => makeRot(state, 'bad', 'not-a-time'), (e) => e.code === 'invalid_expires_at');
  assert.throws(() => makeRot(state, 'bad2', 12345), (e) => e.code === 'invalid_expires_at');
  assert.throws(() => makeRot(state, 'past', '2026-10-05T23:59:59Z'), (e) => e.code === 'invalid_expires_at');
  assert.throws(() => makeRot(state, 'equal', NOW), (e) => e.code === 'invalid_expires_at');
});

test('截止时刻：截止当刻达到门限仍可激活；之后固定为已过期', () => {
  const members = [genKey(), genKey()];
  const { state, domain, makeRot } = makeDeadlineDomain(freshState(), members);
  const deadline = '2026-10-06T01:00:00Z';
  const created = makeRot(state, 'edge', deadline);
  const rot = created.result.rotation;
  const msg = rotation.authorizationMessage(rot);
  const s1 = rotation.submitSignatures(
    created.state, domain.id, 'edge',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msg) }],
    '2026-10-06T00:30:00.000Z',
  ).state;

  // 截止当刻 exactly == expiresAt：允许激活（“截止前”含当刻）
  const atDeadline = rotation.submitSignatures(
    s1, domain.id, 'edge',
    [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msg) }],
    deadline,
  );
  assert.equal(atDeadline.result.activated, true);
  assert.equal(atDeadline.state.domains[domain.id].headDigest, rot.digest);
});

test('截止时刻：仅一份签名后过期 —— 首次补签/读取固化，链头证据竞争候选均不变', () => {
  const members = [genKey(), genKey()];
  const { state, domain, makeRot } = makeDeadlineDomain(freshState(), members);
  const deadline = '2026-10-06T01:00:00Z';
  const created = makeRot(state, 'expire-me', deadline);
  const rot = created.result.rotation;
  const msg = rotation.authorizationMessage(rot);
  // 截止前只收集到 1/2 签名
  const s1 = rotation.submitSignatures(
    created.state, domain.id, 'expire-me',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msg) }],
    '2026-10-06T00:30:00.000Z',
  ).state;
  const headBefore = s1.domains[domain.id].headDigest;
  const checkpointCountBefore = Object.keys(s1.domains[domain.id].checkpoints).length;

  // 截止后首次“读取”（sweep）即固化
  const swept = rotation.sweepExpirations(s1, '2026-10-06T01:00:01.000Z');
  assert.notEqual(swept, s1);
  const expiredRot = swept.domains[domain.id].rotations['expire-me'];
  assert.equal(expiredRot.status, 'expired');
  assert.equal(expiredRot.expiredAt, '2026-10-06T01:00:01.000Z');
  assert.match(expiredRot.rejectedReason, /截止时刻/);
  assert.equal(swept.domains[domain.id].headDigest, headBefore, '固化过期不得推进链头');
  assert.equal(Object.keys(swept.domains[domain.id].checkpoints).length, checkpointCountBefore, '不得新增检查点/证据');

  // 固化后再 sweep 是幂等的（返回同一引用，不落盘）
  assert.equal(rotation.sweepExpirations(swept, '2026-10-06T02:00:00.000Z'), swept);

  // 之后的签名返回稳定拒因
  for (let i = 0; i < 2; i++) {
    assert.throws(
      () => rotation.submitSignatures(swept, domain.id, 'expire-me',
        [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msg) }],
        '2026-10-06T02:00:00.000Z'),
      (e) => e.code === 'rotation_expired',
    );
  }
  // 链头与证据仍不被改写
  const finalDomain = swept.domains[domain.id];
  assert.equal(finalDomain.headDigest, headBefore);
  assert.equal(finalDomain.rotations['expire-me'].signatures.length, 1, '迟到签名不得计入');
  assert.equal(Object.keys(finalDomain.checkpoints).length, checkpointCountBefore);
});

test('截止时刻：截止后首次补签即在同一串行提交中固化并返回稳定拒因', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-deadline-sign-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();
  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '截止域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const next = [genKey(), genKey()];
  const deadline = '2026-10-06T01:00:00Z';
  await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: 'r-exp', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2, expiresAt: deadline }, NOW));
  const rot = store.state.domains[domain.id].rotations['r-exp'];
  const msg = rotation.authorizationMessage(rot);
  const sig0 = sign(members[0].privateKey, msg);
  const sig1 = sign(members[1].privateKey, msg);

  // 截止前一票
  await store.commit((s) => rotation.submitSignatures(s, domain.id, 'r-exp', [{ publicKey: members[0].publicKey, signature: sig0 }], '2026-10-06T00:30:00.000Z'));
  const headBefore = store.state.domains[domain.id].headDigest;

  // 截止后首次补签：拒因 rotation_expired，且固化已落盘
  await assert.rejects(
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r-exp', [{ publicKey: members[1].publicKey, signature: sig1 }], '2026-10-06T01:00:01.000Z')),
    (e) => e.code === 'rotation_expired',
  );
  let onDisk = JSON.parse(fs.readFileSync(store.file, 'utf8'));
  assert.equal(onDisk.domains[domain.id].rotations['r-exp'].status, 'expired', '拒签的同时固化必须已落盘');
  assert.equal(onDisk.domains[domain.id].headDigest, headBefore);

  // 重启后仍能区分已激活/待签/已过期
  const reloaded = new Store(store.file);
  reloaded.load();
  const r = reloaded.state.domains[domain.id].rotations['r-exp'];
  assert.equal(r.status, 'expired');
  assert.equal(r.expiresAt, '2026-10-06T01:00:00.000Z');
  assert.equal(r.signatures.length, 1);
  assert.equal(reloaded.state.domains[domain.id].headDigest, headBefore);
});

test('截止时刻：对其它域的拒签请求也会在同一提交固化到期候选（跨域固化）', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-cross-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();
  const membersA = [genKey(), genKey()];
  const membersB = [genKey(), genKey()];
  const domA = await store.commit((s) => rotation.createDomain(s, { name: '域A', publicKeys: membersA.map((m) => m.publicKey), threshold: 2 }, NOW));
  const domB = await store.commit((s) => rotation.createDomain(s, { name: '域B', publicKeys: membersB.map((m) => m.publicKey), threshold: 2 }, NOW));
  const deadline = '2026-10-06T01:00:00Z';
  await store.commit((s) => rotation.createRotation(s, domA.id, { rotationId: 'a-exp', parentDigest: domA.headDigest, publicKeys: [genKey(), genKey()].map((k) => k.publicKey), threshold: 2, expiresAt: deadline }, NOW));
  await store.commit((s) => rotation.createRotation(s, domB.id, { rotationId: 'b-pending', parentDigest: domB.headDigest, publicKeys: [genKey(), genKey()].map((k) => k.publicKey), threshold: 2 }, NOW));

  // 对域 B 发一个非法批次（空数组 → invalid_batch），此刻域 A 的候选恰好已到截止时刻。
  // sweep 固化发生在拒因之前：即使请求被拒，域 A 的到期固化也必须在同一串行提交落盘。
  await assert.rejects(
    store.commit((s) => rotation.submitSignatures(s, domB.id, 'b-pending', [], '2026-10-06T01:00:01.000Z')),
    (e) => e.code === 'invalid_batch',
  );
  // 内存与磁盘都应已固化域 A 的候选
  assert.equal(store.state.domains[domA.id].rotations['a-exp'].status, 'expired');
  const onDisk = JSON.parse(fs.readFileSync(store.file, 'utf8'));
  assert.equal(onDisk.domains[domA.id].rotations['a-exp'].status, 'expired', '拒签不得吞掉其它域的截止固化');
});

test('截止时刻：并发的末秒达标补签与过期补签只收敛为一个结论（两种入队顺序各一次）', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-last-second-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();
  const members = [genKey(), genKey()];
  const deadline = '2026-10-06T01:00:00Z';

  async function setupDomain(name) {
    const domain = await store.commit((s) => rotation.createDomain(s, { name, publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
    const next = [genKey(), genKey()];
    await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: 'r-last', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2, expiresAt: deadline }, NOW));
    const rot = store.state.domains[domain.id].rotations['r-last'];
    const msg = rotation.authorizationMessage(rot);
    const sig0 = sign(members[0].privateKey, msg);
    const sig1 = sign(members[1].privateKey, msg);
    await store.commit((s) => rotation.submitSignatures(s, domain.id, 'r-last', [{ publicKey: members[0].publicKey, signature: sig0 }], '2026-10-06T00:59:59.000Z'));
    return { domain, rot, sig1 };
  }

  const onTime = (d, sig) => store.commit((s) => rotation.submitSignatures(s, d.id, 'r-last', [{ publicKey: members[1].publicKey, signature: sig }], deadline));
  const afterDeadline = (d, sig) => store.commit((s) => rotation.submitSignatures(s, d.id, 'r-last', [{ publicKey: members[1].publicKey, signature: sig }], '2026-10-06T01:00:01.000Z'));

  // 顺序一：末秒达标补签先入队 → 激活；过期补签得到 rotation_already_activated
  {
    const { domain, rot, sig1 } = await setupDomain('末秒域-达标先到');
    const outcomes = await Promise.allSettled([onTime(domain, sig1), afterDeadline(domain, sig1)]);
    const statuses = outcomes.map((o) => (o.status === 'fulfilled' ? `activated:${o.value.activated}` : `rejected:${o.reason.code}`));
    assert.deepEqual(statuses, ['activated:true', 'rejected:rotation_already_activated'], `达标先到的收敛不符：${statuses}`);
    const d = store.state.domains[domain.id];
    assert.equal(d.rotations['r-last'].status, 'activated');
    assert.equal(d.headDigest, rot.digest);
    assert.equal(d.checkpoints[rot.digest].evidence.length, 2);
  }

  // 顺序二：过期补签先入队 → 固化过期并拒；末秒补签得到 rotation_expired，链头不前进
  {
    const { domain, rot, sig1 } = await setupDomain('末秒域-过期先到');
    const headBefore = store.state.domains[domain.id].headDigest;
    const outcomes = await Promise.allSettled([afterDeadline(domain, sig1), onTime(domain, sig1)]);
    const statuses = outcomes.map((o) => (o.status === 'fulfilled' ? `activated:${o.value.activated}` : `rejected:${o.reason.code}`));
    assert.deepEqual(statuses, ['rejected:rotation_expired', 'rejected:rotation_expired'], `过期先到的收敛不符：${statuses}`);
    const d = store.state.domains[domain.id];
    assert.equal(d.rotations['r-last'].status, 'expired');
    assert.equal(d.headDigest, headBefore);
    assert.notEqual(d.headDigest, rot.digest);
    assert.equal(d.rotations['r-last'].signatures.length, 1);
    assert.equal(d.rotations['r-last'].expiredAt, '2026-10-06T01:00:01.000Z');
  }
});

test('截止时刻：无截止候选保持既有补签与激活行为（兼容）', () => {
  const members = [genKey(), genKey()];
  const { state, domain, makeRot } = makeDeadlineDomain(freshState(), members);
  const created = makeRot(state, 'classic');
  assert.equal(created.result.rotation.expiresAt, null);
  const rot = created.result.rotation;
  const msg = rotation.authorizationMessage(rot);

  // 远在“任意时刻”之后仍可补签激活
  const s1 = rotation.submitSignatures(created.state, domain.id, 'classic',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msg) }],
    '2099-01-01T00:00:00.000Z').state;
  const done = rotation.submitSignatures(s1, domain.id, 'classic',
    [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msg) }],
    '2099-01-01T00:00:01.000Z');
  assert.equal(done.result.activated, true);
  assert.equal(done.state.domains[domain.id].headDigest, rot.digest);
  // sweep 永不过期无截止候选
  assert.equal(rotation.sweepExpirations(done.state, '2099-01-01T00:00:02.000Z'), done.state);
});

test('截止时刻：到期固化不动竞争候选；竞争候选达标激活后过期候选保持过期', () => {
  const members = [genKey(), genKey()];
  const { state, domain } = makeDeadlineDomain(freshState(), members);
  const keysA = [genKey(), genKey()].map((k) => k.publicKey);
  const keysB = [genKey(), genKey()].map((k) => k.publicKey);
  const sA = rotation.createRotation(state, domain.id, { rotationId: 'with-deadline', parentDigest: domain.headDigest, publicKeys: keysA, threshold: 2, expiresAt: '2026-10-06T01:00:00Z' }, NOW).state;
  const sB = rotation.createRotation(sA, domain.id, { rotationId: 'competitor', parentDigest: domain.headDigest, publicKeys: keysB, threshold: 2 }, NOW).state;

  // A 到期固化为过期：竞争候选 B 必须原样保持待签，不被改写
  const swept = rotation.sweepExpirations(sB, '2026-10-06T01:00:30.000Z');
  assert.equal(swept.domains[domain.id].rotations['with-deadline'].status, 'expired');
  assert.equal(swept.domains[domain.id].rotations['competitor'].status, 'pending', '固化过期不得取代竞争候选');

  // B 仍可正常达标激活；A 保持过期、链头只到 B
  const s1 = rotation.submitSignatures(swept, domain.id, 'competitor',
    members.map((m) => ({ publicKey: m.publicKey, signature: sign(m.privateKey, rotation.authorizationMessage(swept.domains[domain.id].rotations.competitor)) })),
    '2026-10-06T02:00:00.000Z');
  assert.equal(s1.result.activated, true);
  const d = s1.state.domains[domain.id];
  assert.equal(d.rotations['with-deadline'].status, 'expired');
  assert.equal(d.rotations['competitor'].status, 'activated');
  assert.equal(d.headDigest, d.rotations['competitor'].digest);
});

test('截止时刻：带截止与不带截止的同标识候选被视为载荷冲突', () => {
  const members = [genKey(), genKey()];
  const { state, domain, nextKeys, makeRot } = makeDeadlineDomain(freshState(), members);
  const created = makeRot(state, 'dup', '2026-10-06T01:00:00Z');
  assert.equal(created.result.created, true);
  // 同标识、同密钥/门限但不带截止时刻 → 载荷不同，冲突拒绝
  assert.throws(
    () => rotation.createRotation(created.state, domain.id,
      { rotationId: 'dup', parentDigest: domain.headDigest, publicKeys: nextKeys, threshold: 2 }, NOW),
    (e) => e.code === 'conflicting_rotation',
  );
  // 相同截止时刻则幂等
  const again = makeRot(created.state, 'dup', '2026-10-06T01:00:00Z');
  assert.equal(again.result.created, false);
  assert.equal(again.state, created.state);
});
