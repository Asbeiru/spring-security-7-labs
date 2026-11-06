type CsrfToken = { token: string; headerName: string };

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function createApiClient(fetcher: typeof fetch = fetch) {
  let csrfPromise: Promise<CsrfToken> | null = null;

  function clearCsrf() {
    csrfPromise = null;
  }

  function csrfToken(): Promise<CsrfToken> {
    if (!csrfPromise) {
      const pending = fetcher('/api/v1/auth/csrf', {
        credentials: 'include', cache: 'no-store'
      }).then(async response => {
        if (!response.ok) throw new ApiError(response.status, '无法获取请求验证令牌');
        return await response.json() as CsrfToken;
      });
      csrfPromise = pending;
      void pending.catch(() => {
        if (csrfPromise === pending) clearCsrf();
      });
    }
    return csrfPromise;
  }

  async function api<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers);
    if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
      const token = await csrfToken();
      headers.set(token.headerName, token.token);
    }
    const response = await fetcher(`/api/v1${path}`, {
      ...options, method, headers, credentials: 'include', cache: 'no-store'
    });
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) clearCsrf();
      let message = response.status === 401 ? '请先登录'
        : response.status === 403 ? '权限不足或请求验证失败' : '请求失败，请稍后再试';
      try {
        const body = await response.json();
        if (typeof body.message === 'string') message = body.message;
      } catch { /* 网关也可能返回非 JSON 响应。 */ }
      throw new ApiError(response.status, message);
    }
    if (response.status === 204) return undefined as T;
    return await response.json() as T;
  }

  async function login(username: string, password: string) {
    await api('/admin/session', {
      method: 'POST', body: new URLSearchParams({ username, password })
    });
    clearCsrf();
  }

  async function logout() {
    await api('/admin/logout', { method: 'POST' });
    clearCsrf();
  }

  return { api, login, logout, clearCsrf };
}
