import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { db } from '../../lib/db.js';
import { createChildLogger } from '../../lib/logger.js';
import { AuditOrchestrator } from '../../services/audit-orchestrator.js';

const logger = createChildLogger('api:audit');

const createAuditSchema = z.object({
  githubUrl: z.string().url().regex(/github\.com/),
  branch: z.string().optional().default('main'),
  commitHash: z.string().optional(),
  config: z.object({
    enableStaticAnalysis: z.boolean().optional().default(true),
    enableAiInference: z.boolean().optional().default(true),
    enableFuzzing: z.boolean().optional().default(false),
    generatePoc: z.boolean().optional().default(true),
    proMode: z.boolean().optional().default(false), // Multi-phase deep analysis
    includePatterns: z.array(z.string()).optional(),
    excludePatterns: z.array(z.string()).optional(),
  }).optional(),
});

export const auditRoutes: FastifyPluginAsync = async (fastify) => {
  const orchestrator = new AuditOrchestrator();

  // Create new audit
  fastify.post('/', {
    schema: {
      description: 'Create a new audit from GitHub repository',
      tags: ['audit'],
      body: {
        type: 'object',
        required: ['githubUrl'],
        properties: {
          githubUrl: { type: 'string' },
          branch: { type: 'string' },
          commitHash: { type: 'string' },
          config: { type: 'object' },
        },
      },
      response: {
        201: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            projectId: { type: 'string' },
            status: { type: 'string' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    const body = createAuditSchema.parse(request.body);
    logger.info({ githubUrl: body.githubUrl }, 'Creating new audit');

    try {
      const result = await orchestrator.createAudit(body);
      return reply.status(201).send(result);
    } catch (error) {
      logger.error({ error }, 'Failed to create audit');
      throw error;
    }
  });

  // Get audit status
  fastify.get('/:id', {
    schema: {
      description: 'Get audit details and status',
      tags: ['audit'],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
    },
  }, async (request) => {
    const { id } = request.params as { id: string };
    
    const audit = await db.audit.findUnique({
      where: { id },
      include: {
        project: true,
        vulnerabilities: {
          include: { poc: true },
          orderBy: [
            { severity: 'asc' },
            { createdAt: 'desc' },
          ],
        },
      },
    });

    if (!audit) {
      throw { statusCode: 404, message: 'Audit not found' };
    }

    return audit;
  });

  // List audits
  fastify.get('/', {
    schema: {
      description: 'List all audits',
      tags: ['audit'],
      querystring: {
        type: 'object',
        properties: {
          status: { type: 'string' },
          limit: { type: 'number', default: 20 },
          offset: { type: 'number', default: 0 },
        },
      },
    },
  }, async (request) => {
    const { status, limit = 20, offset = 0 } = request.query as {
      status?: string;
      limit?: number;
      offset?: number;
    };

    const where = status ? { status: status as any } : {};

    const [audits, total] = await Promise.all([
      db.audit.findMany({
        where,
        include: {
          project: {
            select: { name: true, githubUrl: true },
          },
        },
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
      }),
      db.audit.count({ where }),
    ]);

    return { audits, total, limit, offset };
  });

  // Cancel audit
  fastify.post('/:id/cancel', {
    schema: {
      description: 'Cancel a running audit',
      tags: ['audit'],
    },
  }, async (request) => {
    const { id } = request.params as { id: string };
    
    const audit = await db.audit.update({
      where: { id },
      data: { status: 'CANCELLED' },
    });

    await orchestrator.cancelAudit(id);

    return { id: audit.id, status: audit.status };
  });

  // Get audit findings
  fastify.get('/:id/findings', {
    schema: {
      description: 'Get all findings for an audit',
      tags: ['audit'],
    },
  }, async (request) => {
    const { id } = request.params as { id: string };
    const { severity, category, status } = request.query as {
      severity?: string;
      category?: string;
      status?: string;
    };

    const where: any = { auditId: id };
    if (severity) where.severity = severity;
    if (category) where.category = category;
    if (status) where.status = status;

    const findings = await db.vulnerability.findMany({
      where,
      include: { poc: true, contract: true },
      orderBy: [
        { severity: 'asc' },
        { createdAt: 'desc' },
      ],
    });

    return findings;
  });

  // Re-run PoC for a finding
  fastify.post('/:auditId/findings/:findingId/poc', {
    schema: {
      description: 'Generate or re-run PoC for a finding',
      tags: ['audit'],
    },
  }, async (request) => {
    const { auditId, findingId } = request.params as {
      auditId: string;
      findingId: string;
    };

    const result = await orchestrator.generatePoc(auditId, findingId);
    return result;
  });

  // Update finding status
  fastify.patch('/:auditId/findings/:findingId', {
    schema: {
      description: 'Update finding status (mark as fixed, false positive, etc)',
      tags: ['audit'],
    },
  }, async (request) => {
    const { findingId } = request.params as { findingId: string };
    const { status } = request.body as { status: string };

    const finding = await db.vulnerability.update({
      where: { id: findingId },
      data: { status: status as any },
    });

    return finding;
  });

  // Generate report
  fastify.post('/:id/report', {
    schema: {
      description: 'Generate audit report',
      tags: ['audit'],
    },
  }, async (request) => {
    const { id } = request.params as { id: string };
    const { format = 'markdown' } = request.body as { format?: string };

    const result = await orchestrator.generateReport(id, format);
    return result;
  });
};
