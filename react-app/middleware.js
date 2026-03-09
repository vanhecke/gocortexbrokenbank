import { NextResponse } from 'next/server';

export function middleware(request) {
  const origin = request.headers.get('origin');
  const host = request.headers.get('host');
  const requestHeaders = new Headers(request.headers);

  if (origin) {
    requestHeaders.set('x-forwarded-host', new URL(origin).host);
  } else if (host) {
    requestHeaders.set('x-forwarded-host', host);
  }

  return NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
}

export const config = {
  matcher: '/:path*',
};
