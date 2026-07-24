import Redis from 'ioredis';
import { config } from '../config.js';

/** Shared Redis client for caching + pub/sub (WebSocket fan-out). */
export const redis = new Redis(config.REDIS_URL, {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: false,
});

// A separate connection is required for subscribe mode.
export const redisSub = new Redis(config.REDIS_URL, { lazyConnect: true });

redis.on('error', (err) => {
  // eslint-disable-next-line no-console
  console.error('redis error:', err.message);
});

/**
 * Cache-aside helper: return cached JSON if present, else compute, store with TTL.
 */
export async function cached<T>(
  key: string,
  ttlSeconds: number,
  compute: () => Promise<T>,
): Promise<T> {
  const hit = await redis.get(key);
  if (hit) return JSON.parse(hit) as T;
  const value = await compute();
  await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
  return value;
}

/** Publish an event to a channel (consumed by the WS hub). */
export async function publish(channel: string, payload: unknown): Promise<void> {
  await redis.publish(channel, JSON.stringify(payload));
}
