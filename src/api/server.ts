import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { config } from '../lib/config.js';
import { logger } from '../lib/logger.js';
import { auditRoutes } from './routes/audit.js';
import { projectRoutes } from './routes/project.js';
import { knowledgeBaseRoutes } from './routes/knowledge-base.js';
import { dashboardRoutes } from './routes/dashboard.js';
import { websocketHandler } from './websocket.js';

export async function createServer() {
  const app = Fastify({
    logger: logger,
  });

  // Register plugins
  await app.register(cors, {
    origin: true,
    credentials: true,
  });

  await app.register(websocket);

  await app.register(swagger, {
    openapi: {
      info: {
        title: 'Smart Contract Auditor API',
        description: 'AI-driven smart contract security audit system',
        version: '0.1.0',
      },
      servers: [
        {
          url: `http://${config.host}:${config.port}`,
          description: 'Development server',
        },
      ],
      tags: [
        { name: 'audit', description: 'Audit operations' },
        { name: 'project', description: 'Project management' },
        { name: 'knowledge-base', description: 'Vulnerability knowledge base' },
        { name: 'dashboard', description: 'Dashboard data' },
      ],
    },
  });

  await app.register(swaggerUi, {
    routePrefix: '/docs',
  });

  // Health check
  app.get('/health', async () => {
    return { status: 'ok', timestamp: new Date().toISOString() };
  });

  // API routes
  await app.register(auditRoutes, { prefix: '/api/v1/audit' });
  await app.register(projectRoutes, { prefix: '/api/v1/project' });
  await app.register(knowledgeBaseRoutes, { prefix: '/api/v1/kb' });
  await app.register(dashboardRoutes, { prefix: '/api/v1/dashboard' });

  // WebSocket for real-time updates
  app.register(async function (fastify) {
    fastify.get('/ws', { websocket: true }, websocketHandler);
  });

  return app;
}

async function main() {
  try {
    const server = await createServer();
    
    await server.listen({
      port: config.port,
      host: config.host,
    });

    logger.info(`🚀 Server running at http://${config.host}:${config.port}`);
    logger.info(`📚 API docs at http://${config.host}:${config.port}/docs`);
  } catch (err) {
    logger.error(err);
    process.exit(1);
  }
}

main();
