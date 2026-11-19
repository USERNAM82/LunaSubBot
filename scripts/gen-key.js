// يولّد مفتاحًا سريًا قويًا (64 hex). ضعه في Vercel كـ LUNA_API_KEY وفي البوت (data/panel/api.key أو متغير LUNA_API_KEY).
import crypto from 'node:crypto'
console.log(crypto.randomBytes(32).toString('hex'))
