import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { db } from '../../lib/db.js';
import { KnowledgeBaseService } from '../../services/knowledge-base.js';

const searchSchema = z.object({
  query: z.string().min(1),
  category: z.string().optional(),
  severity: z.string().optional(),
  source: z.string().optional(),
  protocolType: z.string().optional(),
  chain: z.string().optional(),
  dateFrom: z.string().optional(),
  dateTo: z.string().optional(),
  limit: z.coerce.number().default(20),
  offset: z.coerce.number().default(0),
});

export const knowledgeBaseRoutes: FastifyPluginAsync = async (fastify) => {
  const kbService = new KnowledgeBaseService();

  // Search vulnerabilities
  fastify.get('/search', {
    schema: {
      description: 'Search vulnerability knowledge base',
      tags: ['knowledge-base'],
      querystring: {
        type: 'object',
        properties: {
          query: { type: 'string' },
          category: { type: 'string' },
          severity: { type: 'string' },
          source: { type: 'string' },
          protocolType: { type: 'string' },
          chain: { type: 'string' },
          dateFrom: { type: 'string' },
          dateTo: { type: 'string' },
          limit: { type: 'number' },
          offset: { type: 'number' },
        },
      },
    },
  }, async (request) => {
    const params = searchSchema.parse(request.query);
    const results = await kbService.search(params);
    return results;
  });

  // Get vulnerability by ID
  fastify.get('/entry/:id', {
    schema: {
      description: 'Get vulnerability details by ID',
      tags: ['knowledge-base'],
    },
  }, async (request) => {
    const { id } = request.params as { id: string };

    const entry = await db.knowledgeBaseEntry.findUnique({
      where: { id },
    });

    if (!entry) {
      throw { statusCode: 404, message: 'Entry not found' };
    }

    // Get similar vulnerabilities
    const similar = await kbService.findSimilar(id, 5);

    return { entry, similar };
  });

  // Get patterns for detection
  fastify.get('/patterns', {
    schema: {
      description: 'Get vulnerability detection patterns',
      tags: ['knowledge-base'],
      querystring: {
        type: 'object',
        properties: {
          category: { type: 'string' },
          severity: { type: 'string' },
        },
      },
    },
  }, async (request) => {
    const { category, severity } = request.query as {
      category?: string;
      severity?: string;
    };

    const where: any = {};
    if (category) where.category = category;
    if (severity) where.severity = severity;

    const patterns = await db.vulnerabilityPattern.findMany({
      where,
      orderBy: { severity: 'asc' },
    });

    return patterns;
  });

  // Get statistics
  fastify.get('/stats', {
    schema: {
      description: 'Get knowledge base statistics',
      tags: ['knowledge-base'],
    },
  }, async () => {
    const [
      totalEntries,
      byCategory,
      bySeverity,
      bySource,
      byProtocolType,
      recentEntries,
    ] = await Promise.all([
      db.knowledgeBaseEntry.count(),
      db.knowledgeBaseEntry.groupBy({
        by: ['category'],
        _count: true,
      }),
      db.knowledgeBaseEntry.groupBy({
        by: ['severity'],
        _count: true,
      }),
      db.knowledgeBaseEntry.groupBy({
        by: ['source'],
        _count: true,
      }),
      db.knowledgeBaseEntry.groupBy({
        by: ['protocolType'],
        _count: true,
        where: { protocolType: { not: null } },
      }),
      db.knowledgeBaseEntry.findMany({
        orderBy: { createdAt: 'desc' },
        take: 10,
        select: {
          id: true,
          title: true,
          severity: true,
          source: true,
          createdAt: true,
        },
      }),
    ]);

    return {
      total: totalEntries,
      byCategory: Object.fromEntries(
        byCategory.map((c) => [c.category ?? 'unknown', c._count])
      ),
      bySeverity: Object.fromEntries(
        bySeverity.map((s) => [s.severity ?? 'unknown', s._count])
      ),
      bySource: Object.fromEntries(
        bySource.map((s) => [s.source, s._count])
      ),
      byProtocolType: Object.fromEntries(
        byProtocolType.map((p) => [p.protocolType ?? 'unknown', p._count])
      ),
      recentEntries,
    };
  });

  // List sources
  fastify.get('/sources', {
    schema: {
      description: 'List all knowledge base sources',
      tags: ['knowledge-base'],
    },
  }, async () => {
    const sources = await db.knowledgeBaseEntry.groupBy({
      by: ['source'],
      _count: true,
      orderBy: { _count: { source: 'desc' } },
    });

    return sources.map((s) => ({
      name: s.source,
      count: s._count,
    }));
  });

  // Get categories taxonomy
  fastify.get('/categories', {
    schema: {
      description: 'Get vulnerability categories with subcategories',
      tags: ['knowledge-base'],
    },
  }, async () => {
    // Return the taxonomy defined in PRD
    return {
      categories: [
        {
          id: 'ACCESS_CONTROL',
          name: 'Access Control',
          subcategories: [
            'Missing Access Control',
            'Incorrect Access Control', 
            'Privilege Escalation',
            'Front-running',
          ],
        },
        {
          id: 'REENTRANCY',
          name: 'Reentrancy',
          subcategories: [
            'Single-function Reentrancy',
            'Cross-function Reentrancy',
            'Cross-contract Reentrancy',
            'Read-only Reentrancy',
          ],
        },
        {
          id: 'ARITHMETIC',
          name: 'Arithmetic',
          subcategories: [
            'Integer Overflow/Underflow',
            'Precision Loss',
            'Rounding Errors',
            'Division by Zero',
          ],
        },
        {
          id: 'LOGIC_ERROR',
          name: 'Logic Errors',
          subcategories: [
            'Business Logic Flaws',
            'State Machine Violations',
            'Incorrect Calculations',
            'Edge Case Handling',
          ],
        },
        {
          id: 'ORACLE_MANIPULATION',
          name: 'Oracle Manipulation',
          subcategories: [
            'Price Manipulation',
            'TWAP Manipulation',
            'Flash Loan Attacks',
            'Spot Price Dependency',
          ],
        },
        {
          id: 'TOKEN_HANDLING',
          name: 'Token Handling',
          subcategories: [
            'ERC20 Non-standard',
            'Fee-on-transfer Issues',
            'Rebasing Token Issues',
            'Token Balance Manipulation',
          ],
        },
        {
          id: 'EXTERNAL_INTERACTION',
          name: 'External Interactions',
          subcategories: [
            'Unchecked External Calls',
            'Callback Vulnerabilities',
            'Trust Assumptions',
            'Cross-chain Issues',
          ],
        },
        {
          id: 'DATA_VALIDATION',
          name: 'Data Validation',
          subcategories: [
            'Input Validation',
            'Return Value Handling',
            'Array/Mapping Issues',
            'Signature Verification',
          ],
        },
        {
          id: 'GAS_ISSUE',
          name: 'Gas Issues',
          subcategories: [
            'DoS via Gas',
            'Unbounded Loops',
            'Storage vs Memory',
            'Gas Griefing',
          ],
        },
        {
          id: 'PROTOCOL_SPECIFIC',
          name: 'Protocol Specific',
          subcategories: [
            'AMM Issues',
            'Lending Protocol Issues',
            'Governance Issues',
            'Bridge Issues',
          ],
        },
      ],
    };
  });

  // Semantic search (vector)
  fastify.post('/semantic-search', {
    schema: {
      description: 'Semantic search using embeddings',
      tags: ['knowledge-base'],
    },
  }, async (request) => {
    const { query, limit = 10 } = request.body as {
      query: string;
      limit?: number;
    };

    const results = await kbService.semanticSearch(query, limit);
    return results;
  });
};
