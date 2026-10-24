import { NextResponse } from 'next/server';
import { configuredRedisStore } from '@/lib/auth/shared-session-store';
export const dynamic = 'force-dynamic';
export async function GET() {
  try {
    const ready = await (await configuredRedisStore()).ready();
    return NextResponse.json({ ready }, { status: ready ? 200 : 503, headers: { 'Cache-Control': 'no-store' } });
  } catch { return NextResponse.json({ ready: false }, { status: 503, headers: { 'Cache-Control': 'no-store' } }); }
}
