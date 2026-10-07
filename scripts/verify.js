'use strict';

/**
 * 验收入口（compose 中的 verify 服务）：
 *   1. 运行轮换规则单元测试（node --test）；
 *   2. 运行构建检查（scripts/build-check.js）；
 *   3. 对运行中的服务做 HTTP 冒烟：
 *      - 创建二钥、门限为二的设备域；
 *      - 错误父摘要 / 篡改载荷 / 重复重传 / 非成员签名均被拒且链头不变；
 *      - 补齐两名有效签名后，接口可读回已激活链头与两份签名证据；
 *      - 页面渲染出相同结果；
 *      - 激活后的竞争候选与迟到补签被拒；
 *      - 并发竞争候选只收敛为一个活动检查点；
 *      - 应用重启后链头、历史检查点与签名证据保持一致；
 *      - 健康端点反映设备域状态。
 *   全部通过退出码 0，否则退出码 1。
 */

const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const APP_URL = (process.env.APP_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');

let failures = 0;

function pass(name) {
  console.log(`  ✓ ${name}`);
}

function fail(name, detail) {
  failures += 1;
  console.error(`  ✗ ${name}`);
  if (detail) console.error(`    ${String(detail).split('\n').join('\n    ')}`);
}

async function step(name, fn) {
  try {
    await fn();
    pass(name);
  } catch (err) {
    fail(name, err && err.message ? err.message : err);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}（期望 ${expected}，实际 ${actual}）`);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isoIn(seconds) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

function runProcess(args, options = {}) {
  const res = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8', timeout: 120000, ...options });
  return { status: res.status, output: `${res.stdout || ''}${res.stderr || ''}` };
}

async function api(method, urlPath, body) {
  const res = await fetch(`${APP_URL}${urlPath}`, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* 非 JSON 响应（如 HTML 页面） */
  }
  return { status: res.status, json, text };
}

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { publicKey: pub, privateKey };
}

function sign(key, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), key.privateKey).toString('hex');
}

function flipHex(hex) {
  const last = hex.slice(-1);
  const flipped = last === '0' ? '1' : '0';
  return hex.slice(0, -1) + flipped;
}

async function waitForHealth(timeoutMs, predicate) {
  const deadline = Date.now() + timeoutMs;
  let lastError = '未收到响应';
  while (Date.now() < deadline) {
    try {
      const res = await api('GET', '/healthz');
      if (res.status === 200 && res.json && res.json.status === 'ok') {
        if (!predicate || predicate(res.json)) return res.json;
        lastError = '健康响应不满足等待条件';
      } else {
        lastError = `HTTP ${res.status}`;
      }
    } catch (err) {
      lastError = err.message;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`等待服务健康超时：${lastError}`);
}

async function main() {
  console.log(`验收目标：${APP_URL}\n`);

  console.log('— 阶段 1：轮换规则单元测试 —');
  await step('node --test 轮换规则测试全部通过', async () => {
    const res = runProcess(['--test', 'test/']);
    assertEqual(res.status, 0, `单元测试失败：\n${res.output.trim().split('\n').slice(-30).join('\n')}`);
  });

  console.log('— 阶段 2：构建检查 —');
  await step('全部源码语法检查与模块加载检查通过', async () => {
    const res = runProcess([path.join('scripts', 'build-check.js')]);
    assertEqual(res.status, 0, `构建检查失败：\n${res.output}`);
  });

  console.log('— 阶段 3：HTTP 冒烟 —');
  let bootId = null;

  await step('服务健康且健康响应可用于反映设备域状态', async () => {
    const health = await waitForHealth(60000);
    assert(health.bootId && health.startedAt, '健康响应缺少 bootId/startedAt');
    assert(Array.isArray(health.domains), '健康响应缺少设备域列表');
    bootId = health.bootId;
  });

  // —— 验收主域：二钥、门限为二 ——
  const memberA = genKey();
  const memberB = genKey();
  const nextC = genKey();
  const nextD = genKey();
  const outsider = genKey();
  let domainId;
  let genesisHead;
  let rotationDigest;
  let sigA;
  let sigB;

  await step('创建二钥且门限为二的设备域（公钥乱序提交，服务端排序）', async () => {
    const res = await api('POST', '/api/domains', {
      name: '验收域-2of2',
      publicKeys: [memberB.publicKey, memberA.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建设备域失败：${res.text}`);
    domainId = res.json.id;
    const expectedKeys = [memberA.publicKey, memberB.publicKey].sort();
    assert(JSON.stringify(res.json.keys) === JSON.stringify(expectedKeys), '密钥集未按规范排序');
    assertEqual(res.json.generation, 0, '创世代次应为 0');
    genesisHead = res.json.headDigest;
    assert(/^[0-9a-f]{64}$/.test(genesisHead), '链头摘要格式非法');
  });

  await step('健康响应反映新设备域状态', async () => {
    const health = (await api('GET', '/healthz')).json;
    const entry = health.domains.find((d) => d.id === domainId);
    assert(entry, '健康响应中找不到新设备域');
    assertEqual(entry.headDigest, genesisHead, '健康响应中的链头与接口不一致');
  });

  await step('错误父摘要的轮换候选被拒且链头不变', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'bad-parent',
      parentDigest: 'ab'.repeat(32),
      publicKeys: [nextC.publicKey, nextD.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 422, `应返回 422：${res.text}`);
    assertEqual(res.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '链头被错误请求改变');
  });

  await step('创建轮换候选：固定父摘要、下一代次、排序后新公钥集、新门限', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'rot-2026-001',
      parentDigest: genesisHead,
      publicKeys: [nextD.publicKey, nextC.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建轮换失败：${res.text}`);
    rotationDigest = res.json.digest;
    assertEqual(res.json.parentDigest, genesisHead, '父摘要未固定为当前链头');
    assertEqual(res.json.generation, 1, '下一代次应为 1');
    assertEqual(res.json.threshold, 2, '新门限应为 2');
    assert(JSON.stringify(res.json.keys) === JSON.stringify([nextC.publicKey, nextD.publicKey].sort()), '新公钥集未排序');
    assertEqual(res.json.status, 'pending', '候选应处于待签状态');
  });

  await step('篡改载荷与非成员签名被拒且链头不变', async () => {
    const msgRes = await api('GET', `/api/domains/${domainId}/rotations/rot-2026-001/message`);
    assertEqual(msgRes.status, 200, '应能读取规范待签消息');
    const message = msgRes.json.message;
    assert(message.includes(`parent=${genesisHead}`), '待签消息未绑定父摘要');
    sigA = sign(memberA, message);
    sigB = sign(memberB, message);

    const tampered = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: flipHex(sigA) }],
    });
    assertEqual(tampered.json.results[0].code, 'invalid_signature', '篡改签名应给出 invalid_signature');

    const wrongMessage = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sign(memberA, message + '\nforged=1') }],
    });
    assertEqual(wrongMessage.json.results[0].code, 'invalid_signature', '签错消息应给出 invalid_signature');

    const notMember = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: outsider.publicKey, signature: sign(outsider, message) }],
    });
    assertEqual(notMember.json.results[0].code, 'not_parent_member', '非父成员应给出 not_parent_member');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '被拒签名改变了链头');
    assertEqual(head.evidence.length, 0, '被拒签名不应产生证据');
  });

  await step('第一批签名（1/2）：候选保持待签，链头不提前生效', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(res.status, 200, `提交签名失败：${res.text}`);
    assertEqual(res.json.results[0].status, 'accepted', '有效签名应被接受');
    assertEqual(res.json.activated, false, '未达门限不应激活');
    assertEqual(res.json.signers, 1, '应记录 1 名签名者');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '未达门限链头不应前进');
  });

  await step('重传同一签名：给出重复拒因且不改变状态', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(res.json.results[0].code, 'duplicate_signature', '重传应给出 duplicate_signature');
    assertEqual(res.json.signers, 1, '重传不应增加签名者');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '重传不应改变链头');
  });

  await step('补齐第二名有效签名：同一提交中激活，接口读回链头与两份证据', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberB.publicKey, signature: sigB }],
    });
    assertEqual(res.json.results[0].status, 'accepted', '第二名签名应被接受');
    assertEqual(res.json.activated, true, '达到父门限应激活');
    assertEqual(res.json.headDigest, rotationDigest, '链头应前进到候选摘要');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '链头摘要与候选摘要不一致');
    assertEqual(head.generation, 1, '链头代次应为 1');
    assertEqual(head.threshold, 2, '新门限应生效');
    assert(JSON.stringify(head.keys) === JSON.stringify([nextC.publicKey, nextD.publicKey].sort()), '新密钥集应生效');
    assertEqual(head.evidence.length, 2, '应恰好有两份签名证据');
    const evidenceKeys = head.evidence.map((e) => e.publicKey).sort();
    assert(JSON.stringify(evidenceKeys) === JSON.stringify([memberA.publicKey, memberB.publicKey].sort()), '证据签名者不符');
    const evidenceSigs = Object.fromEntries(head.evidence.map((e) => [e.publicKey, e.signature]));
    assertEqual(evidenceSigs[memberA.publicKey], sigA, '成员 A 的签名证据不符');
    assertEqual(evidenceSigs[memberB.publicKey], sigB, '成员 B 的签名证据不符');
  });

  await step('激活后的迟到补签与竞争候选均被拒且链头不变', async () => {
    const late = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(late.status, 409, `迟到补签应返回 409：${late.text}`);
    assertEqual(late.json.error.code, 'rotation_already_activated', '迟到补签应给出拒因');

    const staleParent = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'stale-competitor',
      parentDigest: genesisHead,
      publicKeys: [outsider.publicKey, genKey().publicKey],
      threshold: 2,
    });
    assertEqual(staleParent.status, 422, '旧父摘要的竞争候选应被拒');
    assertEqual(staleParent.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '竞争请求改变了链头');
  });

  // —— 第二设备域：并发竞争只收敛为一个活动检查点 ——
  let domain2Id;
  let domain2Head;
  await step('并发竞争候选：恰好一个激活，其余被取代', async () => {
    const members = [genKey(), genKey()];
    const created = await api('POST', '/api/domains', {
      name: '并发竞争域',
      publicKeys: members.map((m) => m.publicKey),
      threshold: 2,
    });
    assertEqual(created.status, 201, `创建第二设备域失败：${created.text}`);
    domain2Id = created.json.id;
    const parent = created.json.headDigest;

    for (const rid of ['race-1', 'race-2']) {
      const keys = [genKey(), genKey()];
      const res = await api('POST', `/api/domains/${domain2Id}/rotations`, {
        rotationId: rid,
        parentDigest: parent,
        publicKeys: keys.map((k) => k.publicKey),
        threshold: 2,
      });
      assertEqual(res.status, 201, `创建竞争候选失败：${res.text}`);
    }
    const detail = (await api('GET', `/api/domains/${domain2Id}`)).json;
    const batch = (rid) => {
      const rot = detail.rotations.find((r) => r.rotationId === rid);
      return members.map((m) => ({ publicKey: m.publicKey, signature: sign(m, rot.message) }));
    };
    const [r1, r2] = await Promise.all([
      api('POST', `/api/domains/${domain2Id}/rotations/race-1/signatures`, { signatures: batch('race-1') }),
      api('POST', `/api/domains/${domain2Id}/rotations/race-2/signatures`, { signatures: batch('race-2') }),
    ]);
    const outcomes = [r1, r2];
    const activated = outcomes.filter((o) => o.status === 200 && o.json.activated === true);
    const superseded = outcomes.filter((o) => o.status === 409 && o.json.error && o.json.error.code === 'rotation_superseded');
    assertEqual(activated.length, 1, '并发下应恰好一个候选激活');
    assertEqual(superseded.length, 1, '落选候选应给出取代拒因');

    const after = (await api('GET', `/api/domains/${domain2Id}`)).json;
    const activeRotations = after.rotations.filter((r) => r.status === 'activated');
    assertEqual(activeRotations.length, 1, '应只有一个已激活轮换');
    assertEqual(after.headDigest, activeRotations[0].digest, '链头应等于唯一激活候选');
    const gen1 = after.checkpoints.filter((c) => c.generation === 1);
    assertEqual(gen1.length, 1, '同一代次应只有一个活动检查点');
    const loser = after.rotations.find((r) => r.status === 'superseded');
    assert(loser && loser.rejectedReason, '落选候选应记录拒因');
    domain2Head = after.headDigest;
  });

  // —— 截止时刻（维护窗口）验收 ——

  async function make2of2Domain(name) {
    const members = [genKey(), genKey()];
    const created = await api('POST', '/api/domains', {
      name,
      publicKeys: members.map((m) => m.publicKey),
      threshold: 2,
    });
    assertEqual(created.status, 201, `创建设备域失败：${created.text}`);
    return { members, id: created.json.id, head: created.json.headDigest };
  }

  async function createCandidate(domainId, rotationId, parent, keys, threshold, deadline) {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId,
      parentDigest: parent,
      publicKeys: keys.map((k) => k.publicKey),
      threshold,
      ...(deadline ? { deadline } : {}),
    });
    return res;
  }

  function rotMessage(detail, rotationId) {
    const rot = detail.rotations.find((r) => r.rotationId === rotationId);
    assert(rot, `域详情中找不到候选 ${rotationId}`);
    return rot;
  }

  let beforeActivateDeadline;
  await step('截止前激活：窗口内补齐二门限即激活，详情持续给出剩余状态', async () => {
    const { members, id, head } = await make2of2Domain('截止前激活域');
    const next = [genKey(), genKey()];
    const deadline = isoIn(8);
    const created = await createCandidate(id, 'before-deadline', head, next, 2, deadline);
    assertEqual(created.status, 201, `创建候选失败：${created.text}`);
    assertEqual(created.json.deadline, deadline, '候选应回显规范化 UTC 截止时刻');

    // 域详情持续显示剩余状态
    const detail0 = (await api('GET', `/api/domains/${id}`)).json;
    const rot0 = rotMessage(detail0, 'before-deadline');
    assertEqual(rot0.status, 'pending', '新候选应待签');
    assertEqual(rot0.windowOpen, true, '窗口应处于开启状态');
    assert(typeof rot0.remainingMs === 'number' && rot0.remainingMs > 5000, `剩余毫秒异常：${rot0.remainingMs}`);
    assertEqual(detail0.observedAt !== undefined, true, '详情应带观测时刻');

    const msgRes = await api('GET', `/api/domains/${id}/rotations/before-deadline/message`);
    assertEqual(msgRes.json.deadline, deadline, '待签消息端点应回显截止时刻');
    const sigs = members.map((m) => ({ publicKey: m.publicKey, signature: sign(m, msgRes.json.message) }));
    const done = await api('POST', `/api/domains/${id}/rotations/before-deadline/signatures`, { signatures: sigs });
    assertEqual(done.json.activated, true, '截止前达到门限应激活');
    beforeActivateDeadline = done.json.headDigest;

    const after = (await api('GET', `/api/domains/${id}`)).json;
    const rot = rotMessage(after, 'before-deadline');
    assertEqual(rot.status, 'activated', '候选应已激活');
    assertEqual(after.headDigest, beforeActivateDeadline, '链头应前进');
    assertEqual(after.counts.expired, 0, '不应有过期候选');
  });

  let singleSigDomain;
  await step('仅一份签名后过期：截止后读取固定为已过期，链头/证据/竞争候选不改写', async () => {
    const { members, id, head } = await make2of2Domain('单签过期域');
    singleSigDomain = id;
    const next = [genKey(), genKey()];
    const rivalKeys = [genKey(), genKey()];
    const deadline = isoIn(2);
    const created = await createCandidate(id, 'one-sig-expire', head, next, 2, deadline);
    assertEqual(created.status, 201, created.text);
    // 同域下的无截止竞争候选：过期固定不应改写它
    const rival = await createCandidate(id, 'rival-no-window', head, rivalKeys, 2);
    assertEqual(rival.status, 201, rival.text);

    const detail = (await api('GET', `/api/domains/${id}`)).json;
    const msg = rotMessage(detail, 'one-sig-expire').message;
    const rivalMsg = rotMessage(detail, 'rival-no-window').message;

    const one = await api('POST', `/api/domains/${id}/rotations/one-sig-expire/signatures`, {
      signatures: [{ publicKey: members[0].publicKey, signature: sign(members[0], msg) }],
    });
    assertEqual(one.json.activated, false, '仅一份签名不应激活');
    assertEqual(one.json.signers, 1, '应记录 1 名签名者');

    await sleep(2800); // 越过 UTC 截止时刻

    // 截止后首次“读取”即应固定过期
    const swept = (await api('GET', `/api/domains/${id}`)).json;
    const expired = rotMessage(swept, 'one-sig-expire');
    assertEqual(expired.status, 'expired', '读取应把未激活候选固定为已过期');
    assert(expired.expiredAt && expired.deadline === deadline, '应记录截止时刻与固定时刻');
    assertEqual(expired.signers, 1, '截止前的一份签名应予保留');
    assertEqual(swept.headDigest, head, '过期固定不得推进链头');
    assertEqual(swept.checkpoints.length, 1, '过期固定不得产生检查点');
    assertEqual(rotMessage(swept, 'rival-no-window').status, 'pending', '竞争候选不应被改写');
    assertEqual(swept.counts.expired, 1, '摘要计数应有一个已过期');

    // 竞争候选仍可正常收签
    const rivalSig = await api('POST', `/api/domains/${id}/rotations/rival-no-window/signatures`, {
      signatures: [{ publicKey: members[0].publicKey, signature: sign(members[0], rivalMsg) }],
    });
    assertEqual(rivalSig.json.results[0].status, 'accepted', '竞争候选补签应照常接受');
  });

  await step('迟到重传：过期后的补签/重传并发到达只得到一个稳定拒因', async () => {
    const id = singleSigDomain;
    const head = (await api('GET', `/api/domains/${id}`)).json.headDigest;
    const detail = (await api('GET', `/api/domains/${id}`)).json;
    // 过期裁决先于验签：即使用父成员真实公钥搭配伪签名，拒因也必须稳定为 rotation_expired。
    const [memberA, memberB] = detail.keys;
    const fakeSig = '11'.repeat(64);
    const batch = (pub) => ({ signatures: [{ publicKey: pub, signature: fakeSig }] });
    const responses = await Promise.all([
      api('POST', `/api/domains/${id}/rotations/one-sig-expire/signatures`, batch(memberA)),
      api('POST', `/api/domains/${id}/rotations/one-sig-expire/signatures`, batch(memberB)),
      api('POST', `/api/domains/${id}/rotations/one-sig-expire/signatures`, batch(memberA)),
    ]);
    for (const r of responses) {
      assertEqual(r.status, 409, `过期补签应稳定返回 409：${r.text}`);
      assertEqual(r.json.error.code, 'rotation_expired', '稳定拒因应为 rotation_expired');
    }
    const after = (await api('GET', `/api/domains/${id}`)).json;
    const expired = rotMessage(after, 'one-sig-expire');
    assertEqual(expired.status, 'expired', '候选应保持已过期');
    assertEqual(expired.signers, 1, '迟到签名不得写入证据');
    assertEqual(after.headDigest, head, '链头不得被迟到重传改写');
    assertEqual(after.checkpoints.length, 1, '不得产生检查点');
  });

  let firstSigExpireId;
  await step('截止后首次补签即固定：此前无签名的候选在补签时过期固定', async () => {
    const { id, head } = await make2of2Domain('截止首签域');
    const next = [genKey(), genKey()];
    const deadline = isoIn(1);
    const created = await createCandidate(id, 'first-sig-expire', head, next, 2, deadline);
    assertEqual(created.status, 201, created.text);
    await sleep(1800);

    const member = '22'.repeat(32);
    const first = await api('POST', `/api/domains/${id}/rotations/first-sig-expire/signatures`, {
      signatures: [{ publicKey: member, signature: '33'.repeat(64) }],
    });
    assertEqual(first.status, 409, `截止后首次补签应返回 409：${first.text}`);
    assertEqual(first.json.error.code, 'rotation_expired', '首次补签应给出过期拒因并完成固定');

    // 再次补签得到同一稳定拒因
    const second = await api('POST', `/api/domains/${id}/rotations/first-sig-expire/signatures`, {
      signatures: [{ publicKey: member, signature: '33'.repeat(64) }],
    });
    assertEqual(second.status, 409, second.text);
    assertEqual(second.json.error.code, 'rotation_expired', '拒因应保持稳定');

    const detail = (await api('GET', `/api/domains/${id}`)).json;
    const expired = rotMessage(detail, 'first-sig-expire');
    assertEqual(expired.status, 'expired', '读取应确认为已过期');
    assertEqual(expired.signers, 0, '过期当批签名不得落盘');
    assertEqual(detail.headDigest, head, '链头应保持创世');
    firstSigExpireId = id;
  });

  let noWindowId;
  await step('无截止候选兼容：不设窗口的候选跨窗口后仍可补签激活', async () => {
    const { members, id, head } = await make2of2Domain('无窗口兼容域');
    noWindowId = id;
    const next = [genKey(), genKey()];
    const created = await createCandidate(id, 'no-window', head, next, 2);
    assertEqual(created.status, 201, created.text);
    assertEqual(created.json.deadline, null, '未设截止时刻应为 null');
    assertEqual('windowOpen' in created.json, false, '无截止候选不应给出窗口字段');

    const detail = (await api('GET', `/api/domains/${id}`)).json;
    const msg = rotMessage(detail, 'no-window').message;
    const first = await api('POST', `/api/domains/${id}/rotations/no-window/signatures`, {
      signatures: [{ publicKey: members[0].publicKey, signature: sign(members[0], msg) }],
    });
    assertEqual(first.json.activated, false, '第一票后保持待签');

    // 跨越上面其它用例的等待时间后再补第二票（远超任何窗口），仍应激活
    await sleep(200);
    const done = await api('POST', `/api/domains/${id}/rotations/no-window/signatures`, {
      signatures: [{ publicKey: members[1].publicKey, signature: sign(members[1], msg) }],
    });
    assertEqual(done.json.activated, true, '无截止候选应长期可补签并激活');
    const after = (await api('GET', `/api/domains/${id}`)).json;
    assertEqual(after.headDigest, done.json.headDigest, '无截止候选链头应前进');
    assertEqual(rotMessage(after, 'no-window').status, 'activated', '候选应已激活');
  });

  let countdownDomainId;
  let countdownDeadline;
  await step('页面持续显示剩余状态：远未来窗口候选带倒计时标记', async () => {
    const { id, head } = await make2of2Domain('窗口展示域');
    const next = [genKey(), genKey()];
    countdownDeadline = isoIn(3600);
    const created = await createCandidate(id, 'window-open', head, next, 2, countdownDeadline);
    assertEqual(created.status, 201, created.text);
    countdownDomainId = id;
  });

  // —— 重启一致性 ——
  let domain1Before;
  let domain2Before;
  // 剩余毫秒/观测时刻随读取时刻变化，比较持久化状态时剔除这些派生字段。
  function canonicalDetail(detail) {
        return {
          ...detail,
          observedAt: undefined,
          rotations: detail.rotations.map((r) => ({ ...r, remainingMs: undefined, windowOpen: undefined, message: undefined })),
        };
      }
  await step('应用重启后：链头、历史检查点、签名证据与候选状态（含已过期）保持一致', async () => {
    domain1Before = (await api('GET', `/api/domains/${domainId}`)).json;
    domain2Before = (await api('GET', `/api/domains/${domain2Id}`)).json;

    const restart = await api('POST', '/api/admin/restart');
    assertEqual(restart.status, 202, `重启端点应返回 202：${restart.text}`);

    const health = await waitForHealth(60000, (h) => h.bootId !== bootId);
    assert(health.bootId !== bootId, '重启后 bootId 应变化（确为新进程）');

    const domain1After = (await api('GET', `/api/domains/${domainId}`)).json;
    const domain2After = (await api('GET', `/api/domains/${domain2Id}`)).json;
    assert(
      JSON.stringify(canonicalDetail(domain1After)) === JSON.stringify(canonicalDetail(domain1Before)),
      '验收域重启前后状态不一致（链头/检查点/证据丢失）',
    );
    assert(
      JSON.stringify(canonicalDetail(domain2After)) === JSON.stringify(canonicalDetail(domain2Before)),
      '并发域重启前后状态不一致（链头/检查点/证据丢失）',
    );
    const head = (await api('GET', `/api/domains/${domainId}`)).json;
    assertEqual(head.headDigest, rotationDigest, '重启后链头摘要变化');
    assertEqual(head.checkpoints.find((c) => c.digest === rotationDigest).evidence.length, 2, '重启后签名证据份数变化');

    // 重启后仍能区分已激活、待签与已过期候选
    const expiredDomain = (await api('GET', `/api/domains/${singleSigDomain}`)).json;
    assertEqual(rotMessage(expiredDomain, 'one-sig-expire').status, 'expired', '重启后单签候选应为已过期');
    assertEqual(rotMessage(expiredDomain, 'rival-no-window').status, 'pending', '重启后竞争候选应为待签');
    assertEqual(expiredDomain.checkpoints.length, 1, '重启后不应出现过期检查点');

    const firstExpireDomain = (await api('GET', `/api/domains/${firstSigExpireId}`)).json;
    assertEqual(rotMessage(firstExpireDomain, 'first-sig-expire').status, 'expired', '重启后首签过期候选应为已过期');

    const noWindowDomain = (await api('GET', `/api/domains/${noWindowId}`)).json;
    assertEqual(rotMessage(noWindowDomain, 'no-window').status, 'activated', '重启后无截止候选应为已激活');

    const openDomain = (await api('GET', `/api/domains/${countdownDomainId}`)).json;
    const open = rotMessage(openDomain, 'window-open');
    assertEqual(open.status, 'pending', '重启后窗口候选应仍待签');
    assertEqual(open.deadline, countdownDeadline, '重启后截止时刻应保持');
    assertEqual(open.windowOpen, true, '重启后剩余状态应重新计算为窗口开启');
  });

  await step('健康响应在重启后仍反映设备域状态', async () => {
    const health = (await api('GET', '/healthz')).json;
    const d1 = health.domains.find((d) => d.id === domainId);
    const d2 = health.domains.find((d) => d.id === domain2Id);
    assert(d1 && d1.headDigest === rotationDigest, '健康响应中验收域链头不符');
    assert(d2 && d2.headDigest === domain2Head, '健康响应中并发域链头不符');
    const dexp = health.domains.find((d) => d.id === singleSigDomain);
    assert(dexp && dexp.counts.expired === 1, '健康响应应反映 1 个已过期候选');
    const dnw = health.domains.find((d) => d.id === noWindowId);
    assert(dnw && dnw.counts.activated === 1, '健康响应应反映无截止候选已激活');
    assert(health.observedAt, '健康响应应带观测时刻');
  });

  await step('页面显示与接口相同的结果（链头、证据、检查点分组、截止剩余状态）', async () => {
    const page = await api('GET', '/');
    assertEqual(page.status, 200, '页面应可访问');
    assert(page.text.includes(rotationDigest), '页面未显示已激活链头摘要');
    assert(page.text.includes(memberA.publicKey), '页面未显示成员 A 的签名证据');
    assert(page.text.includes(memberB.publicKey), '页面未显示成员 B 的签名证据');
    assert(page.text.includes(sigA), '页面未显示成员 A 的签名值');
    assert(page.text.includes('rot-2026-001'), '页面未显示轮换标识');
    assert(page.text.includes('已激活'), '页面缺少已激活检查点分组');
    assert(page.text.includes('已拒'), '页面缺少已拒检查点分组');
    assert(page.text.includes('待签'), '页面缺少待签检查点分组');
    assert(page.text.includes('race-1') && page.text.includes('race-2'), '页面未显示竞争候选记录');
    // 截止时刻相关展示
    assert(page.text.includes('已过期候选'), '页面缺少已过期候选分组');
    assert(page.text.includes('one-sig-expire'), '页面未显示单签过期候选');
    assert(page.text.includes('UTC 截止时刻'), '页面未显示 UTC 截止时刻');
    assert(page.text.includes('剩余 '), '页面未持续显示剩余时间');
    assert(page.text.includes(countdownDeadline), '页面未显示窗口候选的截止时刻');
    assert(page.text.includes('未设 UTC 截止时刻'), '页面未提示无截止候选长期有效');
    assert(page.text.includes('rival-no-window'), '页面未显示未被改写的竞争候选');
  });

  console.log('');
  if (failures > 0) {
    console.error(`验收失败：${failures} 项未通过`);
    process.exit(1);
  }
  console.log('验收全部通过。');
  process.exit(0);
}

main().catch((err) => {
  console.error(`验收执行异常：${err.stack || err}`);
  process.exit(1);
});
