'use server';

export async function ping() {
  return { status: 'ok', timestamp: Date.now() };
}
