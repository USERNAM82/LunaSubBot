// lib/guard.js — حماية سيرفر Vercel: مسارات مسموحة فقط، CSRF، حد معدّل، وأدوات الكوكي.
const ROUTES = [
  [/^status$/, ['GET']],
  [/^tunnel$/, ['GET']],
  [/^pair$/, ['POST']],
  [/^unpair$/, ['POST']],
  [/^auth\/(request|verify|logout)$/, ['POST']],
  [/^me$/, ['GET']],
  [/^me\/(settings|reconnect|unpair|restore|notifications\/read)$/, ['POST']],
  [/^me\/(notifications|backup)$/, ['GET']],
  [/^me\/support$/, ['GET', 'POST']],
  [/^dev\/(overview|sessions|bans|tickets)$/, ['GET']],
  [/^dev\/(session|ban|unban|capacity)$/, ['POST']],
  [/^dev\/(broadcast|tickets)$/, ['GET', 'POST']]
]

export function routeAllowed(p, method) {
  for (const [re, methods] of ROUTES) if (re.test(p)) return methods.includes(method) ? 'ok' : 'method'
  return 'none'
}

// تشدّد الحاجة لمصدر الطلب: لا يُقبل POST من موقع آخر
export function sameSite(req) {
  const o = req.headers.origin
  if (o) { try { return new URL(o).host === req.headers.host } catch { return false } }
  const sf = req.headers['sec-fetch-site']
  return !sf || sf === 'same-origin' || sf === 'none'
}

const hits = new Map()
export function rateLimited(ip, bucket, max, windowMs = 60_000) {
  const key = bucket + ':' + ip
  const now = Date.now()
  const list = (hits.get(key) || []).filter((t) => now - t < windowMs)
  if (list.length >= max) { hits.set(key, list); return true }
  list.push(now); hits.set(key, list)
  if (hits.size > 5000) for (const [k, l] of hits) if (!l.length || now - l[l.length - 1] > windowMs) hits.delete(k)
  return false
}

export function clientIp(req) {
  const v = String(req.headers['x-vercel-forwarded-for'] || req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || '').split(',')[0].trim()
  return /^[0-9a-fA-F:.]{3,45}$/.test(v) ? v : 'unknown'
}

export function cookieOf(req, name) {
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=')
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim()
  }
  return ''
}

export const setSidCookie = (value, maxAge) =>
  `luna_sid=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`
export const clearSidCookie = () => 'luna_sid=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'

export function readJsonBody(req, limit = 16384) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (c) => {
      size += c.length
      if (size > limit) { reject(new Error('too large')); req.destroy(); return }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}
