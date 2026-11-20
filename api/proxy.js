// api/proxy.js — الوسيط الوحيد بين الواجهة والبوت.
// المتصفح ← (نفس الدومين /api/...) ← هذه الدالة ← (مغلّف مشفّر AES-256-GCM) ← البوت /api/sub/...
// المفتاح السري لا يصل للمتصفح ولا يُرسل في أي ترويسة.
import { callBot, sealCookie, openCookie, getBotUrl, getKey } from '../lib/secure.js'
import { routeAllowed, sameSite, rateLimited, clientIp, cookieOf, setSidCookie, clearSidCookie, readJsonBody } from '../lib/guard.js'

const json = (res, status, obj, headers = {}) => {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers })
  res.end(JSON.stringify(obj))
}
const AUTHY = /^(auth\/|pair$|unpair$)/

// ── وضع التدهور الآمن: إن تعذّر الوصول للبوت لأي سبب (غير مضبوط، متوقف، مفتاح خاطئ، رد غريب...)
// تبقى الواجهة تعمل بشكل طبيعي ويظهر فقط أن النظام غير جاهز؛ لا انهيار ولا 500.
const NOT_READY = { success: false, code: 'system_not_ready', error: '🛠️ النظام غير جاهز حالياً، حاول بعد قليل.' }
// reason: رمز عام للتشخيص فقط (config | timeout | network | redirect | auth | protocol) — افتح /api/status لتعرف السبب
function degrade(res, p, why, reason = 'unknown') {
  if (why) console.warn('[luna] degraded:', reason, why)
  if (p === 'status') return json(res, 200, { online: false, count: 0, max: 0, degraded: true, reason })
  if (p === 'tunnel') return json(res, 200, { url: null })
  return json(res, 503, NOT_READY, { 'Retry-After': '10' })
}
let lastReason = 'network'
let downUntil = 0                       // قاطع دائرة بسيط: بعد فشل الاتصال نرد فورًا 10 ثوانٍ بدل الانتظار والتعليق
const timeoutFor = (p) => (p === 'status' || p === 'tunnel' ? 8_000 : p === 'pair' ? 55_000 : 25_000)
const validBotUrl = (u) => { try { const x = new URL(u); return x.protocol === 'http:' || x.protocol === 'https:' } catch { return false } }

export default async function handler(req, res) {
  try {
    const botUrl = getBotUrl()
    const url = new URL(req.url || '/', 'http://x')
    const p = String(url.searchParams.get('p') || '').replace(/^\/+|\/+$/g, '')
    if (!/^[a-z0-9/_-]{1,60}$/i.test(p)) return json(res, 404, { success: false, error: 'Not found' })
    const method = req.method === 'POST' ? 'POST' : req.method === 'GET' ? 'GET' : ''
    if (!method) return json(res, 405, { success: false, error: 'method_not_allowed' })
    const allowed = routeAllowed(p, method)
    if (allowed === 'none') return json(res, 404, { success: false, error: 'Not found' })
    if (allowed === 'method') return json(res, 405, { success: false, error: 'method_not_allowed' })

    // CSRF: لا POST من موقع آخر، ويجب أن يكون JSON
    if (method === 'POST') {
      if (!sameSite(req)) return json(res, 403, { success: false, code: 'forbidden', error: '⛔ طلب غير مسموح.' })
      const ct = String(req.headers['content-type'] || '')
      let raw = ''
      try { raw = await readJsonBody(req) } catch { return json(res, 413, { success: false, error: 'too_large' }) }
      if (raw.trim() && !ct.includes('application/json')) return json(res, 415, { success: false, code: 'bad_request', error: '⚠️ طلب غير صالح.' })
      req.__raw = raw.trim() ? raw : '{}'
      try { const o = JSON.parse(req.__raw); if (!o || typeof o !== 'object' || Array.isArray(o)) throw 0 } catch { return json(res, 400, { success: false, code: 'bad_request', error: '⚠️ طلب غير صالح.' }) }
    }

    // حد معدّل (على مستوى النسخة الحالية من الدالة؛ والبوت لديه حدوده الخاصة أيضًا)
    const ip = clientIp(req)
    const perMin = Number(process.env.LUNA_RATE_PER_MIN) || 90
    if (rateLimited(ip, 'all', perMin) || (AUTHY.test(p) && rateLimited(ip, 'auth', 12))) {
      return json(res, 429, { success: false, code: 'rate_limited', error: '⏳ طلبات كثيرة. انتظر قليلاً.' }, { 'Retry-After': '30' })
    }

    if (!validBotUrl(botUrl) || !(() => { try { return getKey().length >= 32 } catch { return false } })()) return degrade(res, p, 'LUNA_BOT_URL / LUNA_API_KEY not configured', 'config')
    if (Date.now() < downUntil) return degrade(res, p, '', lastReason)

    const sealed = cookieOf(req, 'luna_sid')
    const session = sealed ? openCookie(sealed) : ''
    const query = [...url.searchParams].filter(([k]) => k !== 'p').map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&')

    let up
    try {
      up = await callBot({ botUrl, path: '/api/sub/' + p, method, body: method === 'POST' ? req.__raw : '', session, ip, query, timeoutMs: timeoutFor(p) })
    } catch (e) {
      downUntil = Date.now() + 10_000
      lastReason = e?.code || 'network'
      return degrade(res, p, `upstream error: ${e?.message || e}`, lastReason)
    }
    downUntil = 0

    let data
    try { data = JSON.parse(up.body) } catch { return degrade(res, p, 'upstream returned non-JSON', 'protocol') }
    if (!data || typeof data !== 'object') return degrade(res, p, 'upstream returned unexpected body', 'protocol')

    const headers = {}
    if (p === 'auth/verify' && up.status === 200 && data?.success && typeof data.session === 'string') {
      headers['Set-Cookie'] = setSidCookie(sealCookie(data.session), Number(data.expiresIn) || 1209600)
      delete data.session
      delete data.expiresIn
    } else if (p === 'auth/logout' || (data?.code === 'unauthorized' && sealed)) {
      headers['Set-Cookie'] = clearSidCookie()
    }
    if (p === 'me/backup' && up.status === 200) headers['Content-Disposition'] = 'attachment; filename="luna-backup.json"'
    return json(res, up.status, data, headers)
  } catch (e) {
    console.error('[luna] handler error:', e?.message || e)
    try { return degrade(res, 'x') } catch { try { res.statusCode = 503; res.end('{"success":false}') } catch {} }
  }
}
