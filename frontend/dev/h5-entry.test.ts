import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import type { Connect, ViteDevServer } from 'vite'
import { h5Entry } from './h5-entry'

const mobile = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile'
const desktop = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/130'

test('原端口 H5 开发分流', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'h5-entry-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const root = path.join(directory, 'dist')
  await mkdir(path.join(root, 'h5-assets'), { recursive: true })
  await writeFile(path.join(root, 'index.html'), '<html>mobile</html>')
  await writeFile(path.join(root, 'h5-assets', 'app.js'), 'export const mobile = true')
  let handler: Connect.NextHandleFunction | undefined
  const plugin = h5Entry(root)
  assert.equal(plugin.apply, 'serve')
  assert.equal(typeof plugin.configureServer, 'function')
  const configure = plugin.configureServer as (server: ViteDevServer) => unknown
  configure({
    middlewares: {
      use(value: Connect.NextHandleFunction) {
        handler = value
      }
    }
  } as ViteDevServer)
  assert.ok(handler)
  const middleware = handler

  async function request(url: string, ua = mobile, method = 'GET') {
    const headers: Record<string, string | number> = {}
    let body: string | undefined
    let continued = false
    const response = {
      statusCode: 200,
      setHeader(name: string, value: string | number) {
        headers[name.toLowerCase()] = value
      },
      end(value?: Buffer) {
        body = value?.toString()
      }
    }
    await middleware(
      { url, method, headers: { 'user-agent': ua } } as IncomingMessage,
      response as unknown as ServerResponse,
      (error?: unknown) => {
        assert.equal(error, undefined)
        continued = true
      }
    )
    return { status: response.statusCode, headers, body, continued }
  }

  for (const [name, url, ua, expected] of [
    ['手机首页', '/', mobile, false],
    ['手机用户登录含查询参数', '/user/login?redirect=%2Fuser%2Flicenses', mobile, false],
    ['手机代理登录', '/agent-panel/login', mobile, false],
    ['手机管理登录', '/admin', mobile, false],
    ['手机 index', '/index.html', mobile, false],
    ['电脑保持 PC', '/admin', desktop, true],
    ['窄屏桌面标识保持 PC', '/user/login', desktop, true],
    ['安装页面保持 PC', '/install', mobile, true],
    ['安装子路由保持 PC', '/install/database', mobile, true],
    ['API 保留代理', '/api/system-config/public', mobile, true],
    ['人脸流程保持原路由', '/realname-face/start', mobile, true],
    ['应用下载保持原路由', '/admin/app-store/download', mobile, true],
    ['PC 资源保持 Vite', '/assets/app.js', mobile, true],
    ['PC 开发资源保持 Vite', '/@vite/client', mobile, true]
  ] as const) {
    await t.test(name, async () => {
      const result = await request(url, ua)
      assert.equal(result.continued, expected)
      if (!expected) {
        assert.equal(result.status, 200)
        assert.equal(result.body, '<html>mobile</html>')
        assert.equal(result.headers.vary, 'User-Agent')
        assert.equal(result.headers['cache-control'], 'no-cache')
        assert.equal(result.headers.location, undefined)
      }
    })
  }
  await t.test('H5 资源不随浏览器标识变化', async () => {
    const phone = await request('/h5-assets/app.js')
    const pc = await request('/h5-assets/app.js', desktop)
    assert.deepEqual(phone, pc)
    assert.equal(phone.body, 'export const mobile = true')
    assert.equal(phone.headers['content-type'], 'text/javascript; charset=utf-8')
  })
  for (const url of [
    '/h5-assets/missing.js',
    '/h5-assets',
    '/h5-assets/app.map',
    '/h5-assets/%2e%2e/index.html',
    '/h5-assets/%5csecret.js'
  ]) {
    await t.test(`缺失或非法资源 ${url} 返回 404`, async () => {
      const result = await request(url)
      assert.equal(result.status, 404)
      assert.equal(result.continued, false)
      assert.equal(result.body, undefined)
    })
  }
  await t.test('目录外软链资源不可公开', async () => {
    await writeFile(path.join(directory, 'secret.js'), 'secret')
    await symlink(path.join(directory, 'secret.js'), path.join(root, 'h5-assets', 'link.js'))
    assert.equal((await request('/h5-assets/link.js')).status, 404)
  })
  await t.test('HEAD 无正文，非读取方法返回 405', async () => {
    const result = await request('/admin', mobile, 'HEAD')
    assert.equal(result.status, 200)
    assert.equal(result.body, undefined)
    assert.equal(result.headers['content-length'], Buffer.byteLength('<html>mobile</html>'))
    const post = await request('/admin', mobile, 'POST')
    assert.equal(post.status, 405)
    assert.equal(post.headers.allow, 'GET, HEAD')
  })
  await t.test('入口移走或为空时回退，重新发布无需重启', async () => {
    await rm(path.join(root, 'index.html'))
    assert.equal((await request('/admin')).continued, true)
    await writeFile(path.join(root, 'index.html'), '')
    assert.equal((await request('/admin')).continued, true)
    await writeFile(path.join(root, 'index.html'), '<html>updated</html>')
    assert.equal((await request('/admin')).body, '<html>updated</html>')
  })
})
