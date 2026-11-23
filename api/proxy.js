// 선택 사항 — 공개 CORS 프록시가 막힐 때를 위한 Vercel Edge 프록시.
// 사용하려면 이 파일을 프로젝트의 api/proxy.js 로 옮겨서 배포하세요.
// index.html 은 /api/proxy 가 있으면 자동으로 가장 먼저 사용합니다.
// 같은 사이트(브라우저의 Sec-Fetch-Site: same-origin)에서 온 요청만 허용합니다.
export const config = { runtime: 'edge' };

const PRIVATE = /^(localhost|0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[.*\]$|.*\.(local|internal)$)/i;
const PASS = ['content-type', 'content-length', 'content-range', 'accept-ranges', 'last-modified', 'etag'];

export default async function handler(req) {
  const site = req.headers.get('sec-fetch-site');
  if (site && site !== 'same-origin') return new Response('forbidden', { status: 403 });

  const target = new URL(req.url).searchParams.get('url');
  let t;
  try { t = new URL(target); } catch { return new Response('bad url', { status: 400 }); }
  if (!/^https?:$/.test(t.protocol) || PRIVATE.test(t.hostname)) return new Response('blocked', { status: 400 });

  const headers = new Headers({
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36',
    accept: req.headers.get('accept') || '*/*',
    referer: t.origin + '/'
  });
  const range = req.headers.get('range');
  if (range) headers.set('range', range);

  let up;
  try { up = await fetch(t, { headers, redirect: 'follow' }); }
  catch { return new Response('upstream error', { status: 502 }); }

  const out = new Headers();
  for (const h of PASS) {
    if (h === 'content-length' && up.headers.get('content-encoding')) continue;
    const v = up.headers.get(h); if (v) out.set(h, v);
  }
  out.set('x-bannerblock', '1');            // index.html 이 이 헤더로 프록시 존재를 확인합니다
  out.set('cache-control', 'no-store');
  return new Response(up.body, { status: up.status, headers: out });
}
