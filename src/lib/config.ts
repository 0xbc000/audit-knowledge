import { config as dotenvConfig } from 'dotenv';
import { z } from 'zod';

dotenvConfig();

const configSchema = z.object({
  // Server
  port: z.coerce.number().default(3000),
  host: z.string().default('0.0.0.0'),
  nodeEnv: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  databaseUrl: z.string(),

  // Redis
  redisUrl: z.string().default('redis://localhost:6379'),

  // Vector DB
  qdrantUrl: z.string().default('http://localhost:6333'),

  // Object Storage
  s3Endpoint: z.string().optional(),
  s3AccessKey: z.string().optional(),
  s3SecretKey: z.string().optional(),
  s3Bucket: z.string().default('sca-storage'),

  // AI
  anthropicApiKey: z.string().optional(),
  openaiApiKey: z.string().optional(),
  defaultAiModel: z.string().default('claude-sonnet-4-20250514'),

  // GitHub
  githubToken: z.string().optional(),

  // Ethereum RPC
  ethRpcUrl: z.string().optional(),
  ethRpcUrlMainnet: z.string().optional(),
  ethRpcUrlArbitrum: z.string().optional(),
  ethRpcUrlPolygon: z.string().optional(),

  // Logging
  logLevel: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),
});

function loadConfig() {
  const result = configSchema.safeParse({
    port: process.env.PORT,
    host: process.env.HOST,
    nodeEnv: process.env.NODE_ENV,
    databaseUrl: process.env.DATABASE_URL,
    redisUrl: process.env.REDIS_URL,
    qdrantUrl: process.env.QDRANT_URL,
    s3Endpoint: process.env.S3_ENDPOINT,
    s3AccessKey: process.env.S3_ACCESS_KEY,
    s3SecretKey: process.env.S3_SECRET_KEY,
    s3Bucket: process.env.S3_BUCKET,
    anthropicApiKey: process.env.ANTHROPIC_API_KEY,
    openaiApiKey: process.env.OPENAI_API_KEY,
    defaultAiModel: process.env.DEFAULT_AI_MODEL,
    githubToken: process.env.GITHUB_TOKEN,
    ethRpcUrl: process.env.ETH_RPC_URL,
    ethRpcUrlMainnet: process.env.ETH_RPC_URL_MAINNET,
    ethRpcUrlArbitrum: process.env.ETH_RPC_URL_ARBITRUM,
    ethRpcUrlPolygon: process.env.ETH_RPC_URL_POLYGON,
    logLevel: process.env.LOG_LEVEL,
  });

  if (!result.success) {
    console.error('❌ Invalid configuration:');
    console.error(result.error.format());
    process.exit(1);
  }

  return result.data;
}

export const config = loadConfig();

export type Config = z.infer<typeof configSchema>;
