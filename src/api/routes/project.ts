import { FastifyPluginAsync } from 'fastify';
import { db } from '../../lib/db.js';

export const projectRoutes: FastifyPluginAsync = async (fastify) => {
  // List projects
  fastify.get('/', {
    schema: {
      description: 'List all projects',
      tags: ['project'],
      querystring: {
        type: 'object',
        properties: {
          protocolType: { type: 'string' },
          limit: { type: 'number', default: 20 },
          offset: { type: 'number', default: 0 },
        },
      },
    },
  }, async (request) => {
    const { protocolType, limit = 20, offset = 0 } = request.query as {
      protocolType?: string;
      limit?: number;
      offset?: number;
    };

    const where = protocolType ? { protocolType: protocolType as any } : {};

    const [projects, total] = await Promise.all([
      db.project.findMany({
        where,
        include: {
          _count: {
            select: { contracts: true, audits: true },
          },
        },
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
      }),
      db.project.count({ where }),
    ]);

    return { projects, total, limit, offset };
  });

  // Get project details
  fastify.get('/:id', {
    schema: {
      description: 'Get project details',
      tags: ['project'],
    },
  }, async (request) => {
    const { id } = request.params as { id: string };

    const project = await db.project.findUnique({
      where: { id },
      include: {
        contracts: {
          select: {
            id: true,
            name: true,
            filePath: true,
            lines: true,
            riskScore: true,
          },
        },
        dependencies: true,
        audits: {
          orderBy: { createdAt: 'desc' },
          take: 5,
        },
      },
    });

    if (!project) {
      throw { statusCode: 404, message: 'Project not found' };
    }

    return project;
  });

  // Get project contracts
  fastify.get('/:id/contracts', {
    schema: {
      description: 'Get all contracts in a project',
      tags: ['project'],
    },
  }, async (request) => {
    const { id } = request.params as { id: string };

    const contracts = await db.contract.findMany({
      where: { projectId: id },
      include: {
        functions: {
          select: {
            id: true,
            name: true,
            visibility: true,
            riskScore: true,
          },
        },
        _count: {
          select: { vulnerabilities: true },
        },
      },
      orderBy: { riskScore: 'desc' },
    });

    return contracts;
  });

  // Get contract source code
  fastify.get('/:projectId/contracts/:contractId/source', {
    schema: {
      description: 'Get contract source code with analysis data',
      tags: ['project'],
    },
  }, async (request) => {
    const { contractId } = request.params as { contractId: string };

    const contract = await db.contract.findUnique({
      where: { id: contractId },
      include: {
        functions: true,
        vulnerabilities: {
          select: {
            id: true,
            severity: true,
            title: true,
            startLine: true,
            endLine: true,
          },
        },
      },
    });

    if (!contract) {
      throw { statusCode: 404, message: 'Contract not found' };
    }

    return contract;
  });

  // Delete project
  fastify.delete('/:id', {
    schema: {
      description: 'Delete a project and all associated data',
      tags: ['project'],
    },
  }, async (request, reply) => {
    const { id } = request.params as { id: string };

    await db.project.delete({ where: { id } });

    return reply.status(204).send();
  });
};
