import { readFile, realpath, stat } from 'node:fs/promises'
import path from 'node:path'
import type { Plugin } from 'vite'

const mobileUA = /iphone|ipad|ipod|android|mobile|windows phone|iemobile|blackberry|opera mini/i
const assetTypes: Record<string, string> = {
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.wasm': 'application/wasm',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mp3': 'audio/mpeg',
  '.ogg': 'audio/ogg',
  '.wav': 'audio/wav',
  '.pdf': 'application/pdf'
}

// 开发环境复用 PC 监听端口，只公开移动构建产物，Git 克隆缺少 H5 时仍可运行 PC。
export function h5Entry(directory: string): Plugin {
  return {
    name: 'same-port-h5-entry',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        let pathname: string
        try {
          pathname = decodeURIComponent((req.url || '/').split('?')[0])
        } catch {
          res.statusCode = 400
          res.end()
          return
        }
        const isAsset = pathname === '/h5-assets' || pathname.startsWith('/h5-assets/')
        const isPage =
          (pathname === '/index.html' || !path.posix.extname(pathname)) &&
          !/^\/(?:api|realname-face|admin\/app-store|install|assets|@[^/]*|src|node_modules)(?:\/|$)/.test(
            pathname
          ) &&
          !isAsset
        if (!isAsset && !isPage) return next()
        if (isPage) {
          res.setHeader('Vary', 'User-Agent')
          res.setHeader('Cache-Control', 'no-cache')
          if (!mobileUA.test(req.headers['user-agent'] || '')) return next()
        }
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.statusCode = 405
          res.setHeader('Allow', 'GET, HEAD')
          res.end()
          return
        }
        if (
          isAsset &&
          (/[\\\x00%:]/.test(pathname) ||
            pathname
              .split('/')
              .slice(1)
              .some((part) => !part || part.startsWith('.')))
        ) {
          res.statusCode = 404
          res.end()
          return
        }
        const contentType = isAsset
          ? assetTypes[path.extname(pathname).toLowerCase()]
          : 'text/html; charset=utf-8'
        if (!contentType) {
          res.statusCode = 404
          res.end()
          return
        }
        try {
          const root = await realpath(directory)
          const filename = await realpath(
            path.join(root, isAsset ? pathname.slice(1) : 'index.html')
          )
          const relative = path.relative(root, filename)
          if (relative.startsWith('..') || path.isAbsolute(relative)) {
            res.statusCode = 404
            res.end()
            return
          }
          const info = await stat(filename)
          if (!info.isFile() || (!isAsset && info.size === 0)) {
            if (isPage) return next()
            res.statusCode = 404
            res.end()
            return
          }
          // 每次重新读取入口，构建更新和移走入口均无需重启 Vite。
          const body = await readFile(filename)
          res.setHeader('Content-Type', contentType)
          res.setHeader('Content-Length', body.length)
          res.setHeader('Cache-Control', 'no-cache')
          res.setHeader('X-Content-Type-Options', 'nosniff')
          res.end(req.method === 'HEAD' ? undefined : body)
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code
          if (!['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'].includes(code || '')) return next(error)
          if (isPage) return next()
          res.statusCode = 404
          res.end()
        }
      })
    }
  }
}
