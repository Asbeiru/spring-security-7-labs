import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiClient, ApiError } from './api.ts';

function fakeServer(handler = () => new Response(null, { status: 204 })) {
  const calls = [];
  let tokens = 0;
  const fetcher = async (url, options = {}) => {
    calls.push({ url, ...options });
    if (url === '/api/v1/auth/csrf') {
      return Response.json({ token: `token-${++tokens}`, headerName: 'X-CSRF-TOKEN' });
    }
    return handler(url, options);
  };
  return { calls, client: createApiClient(fetcher) };
}

test('lowercase get does not fetch a CSRF token', async () => {
  const { calls, client } = fakeServer(() => Response.json({ articles: [] }));
  await client.api('/articles', { method: 'get' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'GET');
  assert.equal(calls[0].headers.has('X-CSRF-TOKEN'), false);
});

test('concurrent writes share one pending handshake', async () => {
  const { calls, client } = fakeServer();
  await Promise.all([
    client.api('/admin/articles', { method: 'POST' }),
    client.api('/admin/articles', { method: 'POST' })
  ]);
  assert.equal(calls.filter(call => call.url.endsWith('/auth/csrf')).length, 1);
  assert.deepEqual(calls.filter(call => call.method === 'POST')
    .map(call => call.headers.get('X-CSRF-TOKEN')), ['token-1', 'token-1']);
});

test('successful login clears the pre-login token before first write', async () => {
  const { calls, client } = fakeServer();
  await client.login('admin', 'demo-only-123');
  await client.api('/admin/articles', { method: 'POST' });
  assert.deepEqual(calls.map(call => call.url), [
    '/api/v1/auth/csrf', '/api/v1/admin/session',
    '/api/v1/auth/csrf', '/api/v1/admin/articles'
  ]);
  assert.equal(calls[1].headers.get('X-CSRF-TOKEN'), 'token-1');
  assert.equal(calls[3].headers.get('X-CSRF-TOKEN'), 'token-2');
  assert.equal(calls[1].body.get('username'), 'admin');
  assert.ok(calls.every(call => call.credentials === 'include'));
});

test('logout clears its token before a later login', async () => {
  const { calls, client } = fakeServer();
  await client.login('admin', 'demo-only-123');
  await client.logout();
  await client.login('admin', 'demo-only-123');
  assert.deepEqual(calls.filter(call => call.method === 'POST')
    .map(call => call.headers.get('X-CSRF-TOKEN')), ['token-1', 'token-2', 'token-3']);
});

for (const status of [401, 403]) {
  test(`${status} clears cached token and throws without replaying the write`, async () => {
    let reject = true;
    const { calls, client } = fakeServer(() => reject
      ? Response.json({ message: status === 403 ? '权限不足' : '请先登录' }, { status })
      : new Response(null, { status: 204 }));
    await assert.rejects(client.api('/admin/articles', { method: 'POST' }), error =>
      error instanceof ApiError && error.status === status);
    assert.equal(calls.filter(call => call.method === 'POST').length, 1);
    reject = false;
    await client.api('/admin/articles', { method: 'POST' });
    assert.equal(calls.filter(call => call.url.endsWith('/auth/csrf')).length, 2);
    assert.equal(calls.at(-1).headers.get('X-CSRF-TOKEN'), 'token-2');
  });
}

test('a failed handshake is retried later and does not submit the write', async () => {
  const calls = [];
  let fail = true;
  const client = createApiClient(async (url, options = {}) => {
    calls.push({ url, ...options });
    if (url.endsWith('/auth/csrf')) {
      if (fail) return new Response(null, { status: 503 });
      return Response.json({ token: 'fresh', headerName: 'X-CSRF-TOKEN' });
    }
    return new Response(null, { status: 204 });
  });
  await assert.rejects(client.api('/admin/articles', { method: 'POST' }), ApiError);
  assert.equal(calls.length, 1);
  fail = false;
  await client.api('/admin/articles', { method: 'POST' });
  assert.equal(calls.length, 3);
});

test('a non-JSON error keeps the status and the generic permission message', async () => {
  const { client } = fakeServer(() => new Response('<html>Forbidden</html>', { status: 403 }));
  await assert.rejects(client.api('/admin/articles', { method: 'POST' }), error =>
    error.status === 403 && error.message === '权限不足或请求验证失败');
});
