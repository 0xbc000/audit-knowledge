import { PrismaClient } from '@prisma/client';
import { createChildLogger } from './logger.js';

const logger = createChildLogger('db');

declare global {
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

export const db = globalThis.prisma ?? new PrismaClient({
  log: [
    { emit: 'event', level: 'query' },
    { emit: 'event', level: 'error' },
    { emit: 'event', level: 'warn' },
  ],
});

if (process.env.NODE_ENV !== 'production') {
  globalThis.prisma = db;
}

// Log queries in development
db.$on('query' as never, (e: { query: string; duration: number }) => {
  logger.debug({ query: e.query, duration: e.duration }, 'Database query');
});

db.$on('error' as never, (e: { message: string }) => {
  logger.error({ error: e.message }, 'Database error');
});

export async function connectDb() {
  try {
    await db.$connect();
    logger.info('✅ Connected to database');
  } catch (error) {
    logger.error({ error }, 'Failed to connect to database');
    throw error;
  }
}

export async function disconnectDb() {
  await db.$disconnect();
  logger.info('Disconnected from database');
}
