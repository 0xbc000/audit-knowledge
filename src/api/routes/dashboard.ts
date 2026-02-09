import { FastifyPluginAsync } from 'fastify';
import { db } from '../../lib/db.js';

export const dashboardRoutes: FastifyPluginAsync = async (fastify) => {
  // Get dashboard overview
  fastify.get('/overview', {
    schema: {
      description: 'Get dashboard overview statistics',
      tags: ['dashboard'],
    },
  }, async () => {
    const [
      totalProjects,
      totalAudits,
      activeAudits,
      totalFindings,
      criticalFindings,
      verifiedPocs,
      recentAudits,
      findingsBySeverity,
      findingsByCategory,
      auditsByMonth,
    ] = await Promise.all([
      // Total projects
      db.project.count(),
      
      // Total audits
      db.audit.count(),
      
      // Active audits
      db.audit.count({
        where: { status: { in: ['QUEUED', 'IN_PROGRESS'] } },
      }),
      
      // Total findings
      db.vulnerability.count(),
      
      // Critical findings
      db.vulnerability.count({
        where: { severity: 'CRITICAL' },
      }),
      
      // Verified PoCs
      db.proofOfConcept.count({
        where: { verified: true },
      }),
      
      // Recent audits
      db.audit.findMany({
        orderBy: { createdAt: 'desc' },
        take: 10,
        include: {
          project: {
            select: { name: true, githubUrl: true },
          },
        },
      }),
      
      // Findings by severity
      db.vulnerability.groupBy({
        by: ['severity'],
        _count: true,
      }),
      
      // Findings by category
      db.vulnerability.groupBy({
        by: ['category'],
        _count: true,
      }),
      
      // Audits by month (last 6 months)
      db.$queryRaw`
        SELECT 
          DATE_TRUNC('month', "createdAt") as month,
          COUNT(*) as count
        FROM "Audit"
        WHERE "createdAt" >= NOW() - INTERVAL '6 months'
        GROUP BY DATE_TRUNC('month', "createdAt")
        ORDER BY month DESC
      ` as Promise<{ month: Date; count: bigint }[]>,
    ]);

    return {
      stats: {
        totalProjects,
        totalAudits,
        activeAudits,
        totalFindings,
        criticalFindings,
        verifiedPocs,
        pocSuccessRate: totalFindings > 0 
          ? Math.round((verifiedPocs / totalFindings) * 100) 
          : 0,
      },
      recentAudits,
      charts: {
        findingsBySeverity: Object.fromEntries(
          findingsBySeverity.map((f) => [f.severity, f._count])
        ),
        findingsByCategory: Object.fromEntries(
          findingsByCategory.map((f) => [f.category, f._count])
        ),
        auditsByMonth: auditsByMonth.map((a) => ({
          month: a.month,
          count: Number(a.count),
        })),
      },
    };
  });

  // Get audit trends
  fastify.get('/trends', {
    schema: {
      description: 'Get vulnerability trends over time',
      tags: ['dashboard'],
    },
  }, async (request) => {
    const { period = '30d' } = request.query as { period?: string };

    let interval: string;
    let dateFilter: Date;

    switch (period) {
      case '7d':
        interval = '1 day';
        dateFilter = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        interval = '1 day';
        dateFilter = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        break;
      case '90d':
        interval = '1 week';
        dateFilter = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
        break;
      case '1y':
        interval = '1 month';
        dateFilter = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);
        break;
      default:
        interval = '1 day';
        dateFilter = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    }

    const trends = await db.$queryRaw`
      SELECT 
        DATE_TRUNC('day', "createdAt") as date,
        "severity",
        COUNT(*) as count
      FROM "Vulnerability"
      WHERE "createdAt" >= ${dateFilter}
      GROUP BY DATE_TRUNC('day', "createdAt"), "severity"
      ORDER BY date ASC
    ` as { date: Date; severity: string; count: bigint }[];

    return trends.map((t) => ({
      date: t.date,
      severity: t.severity,
      count: Number(t.count),
    }));
  });

  // Get top vulnerable patterns
  fastify.get('/top-vulnerabilities', {
    schema: {
      description: 'Get most common vulnerability patterns',
      tags: ['dashboard'],
    },
  }, async (request) => {
    const { limit = 10 } = request.query as { limit?: number };

    const topVulns = await db.vulnerability.groupBy({
      by: ['category', 'title'],
      _count: true,
      orderBy: { _count: { category: 'desc' } },
      take: limit,
    });

    return topVulns.map((v) => ({
      category: v.category,
      title: v.title,
      count: v._count,
    }));
  });

  // Get accuracy metrics
  fastify.get('/accuracy', {
    schema: {
      description: 'Get detection accuracy metrics',
      tags: ['dashboard'],
    },
  }, async () => {
    const [total, verified, falsePositives, fixed] = await Promise.all([
      db.vulnerability.count(),
      db.vulnerability.count({ where: { status: 'VERIFIED' } }),
      db.vulnerability.count({ where: { status: 'FALSE_POSITIVE' } }),
      db.vulnerability.count({ where: { status: 'FIXED' } }),
    ]);

    const truePositives = verified + fixed;
    const precision = total > 0 
      ? (truePositives / (total - falsePositives)) * 100 
      : 0;

    return {
      total,
      verified,
      falsePositives,
      fixed,
      detected: total - verified - falsePositives - fixed,
      precision: Math.round(precision * 100) / 100,
      falsePositiveRate: total > 0 
        ? Math.round((falsePositives / total) * 10000) / 100 
        : 0,
    };
  });

  // Get protocol type distribution
  fastify.get('/protocols', {
    schema: {
      description: 'Get vulnerability distribution by protocol type',
      tags: ['dashboard'],
    },
  }, async () => {
    const distribution = await db.project.groupBy({
      by: ['protocolType'],
      _count: true,
      where: { protocolType: { not: null } },
    });

    // Get findings per protocol type
    const findingsPerProtocol = await db.$queryRaw`
      SELECT 
        p."protocolType",
        COUNT(v.id) as findings,
        COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) as critical,
        COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) as high
      FROM "Project" p
      LEFT JOIN "Audit" a ON a."projectId" = p.id
      LEFT JOIN "Vulnerability" v ON v."auditId" = a.id
      WHERE p."protocolType" IS NOT NULL
      GROUP BY p."protocolType"
    ` as { protocolType: string; findings: bigint; critical: bigint; high: bigint }[];

    return {
      distribution: Object.fromEntries(
        distribution.map((d) => [d.protocolType, d._count])
      ),
      findings: findingsPerProtocol.map((f) => ({
        protocolType: f.protocolType,
        total: Number(f.findings),
        critical: Number(f.critical),
        high: Number(f.high),
      })),
    };
  });

  // Get recent activity feed
  fastify.get('/activity', {
    schema: {
      description: 'Get recent activity feed',
      tags: ['dashboard'],
    },
  }, async (request) => {
    const { limit = 20 } = request.query as { limit?: number };

    const [recentAudits, recentFindings, recentPocs] = await Promise.all([
      db.audit.findMany({
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: {
          id: true,
          status: true,
          createdAt: true,
          project: { select: { name: true } },
        },
      }),
      db.vulnerability.findMany({
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: {
          id: true,
          title: true,
          severity: true,
          createdAt: true,
          audit: {
            select: {
              project: { select: { name: true } },
            },
          },
        },
      }),
      db.proofOfConcept.findMany({
        orderBy: { createdAt: 'desc' },
        take: limit,
        where: { verified: true },
        select: {
          id: true,
          verified: true,
          createdAt: true,
          vulnerability: {
            select: { title: true, severity: true },
          },
        },
      }),
    ]);

    // Combine and sort by date
    const activities = [
      ...recentAudits.map((a) => ({
        type: 'audit' as const,
        id: a.id,
        title: `Audit ${a.status.toLowerCase()}: ${a.project.name}`,
        status: a.status,
        createdAt: a.createdAt,
      })),
      ...recentFindings.map((f) => ({
        type: 'finding' as const,
        id: f.id,
        title: f.title,
        severity: f.severity,
        project: f.audit.project.name,
        createdAt: f.createdAt,
      })),
      ...recentPocs.map((p) => ({
        type: 'poc' as const,
        id: p.id,
        title: `PoC verified: ${p.vulnerability.title}`,
        severity: p.vulnerability.severity,
        createdAt: p.createdAt,
      })),
    ].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
     .slice(0, limit);

    return activities;
  });

  // Compare audits
  fastify.get('/compare', {
    schema: {
      description: 'Compare findings between two audits',
      tags: ['dashboard'],
      querystring: {
        type: 'object',
        required: ['auditA', 'auditB'],
        properties: {
          auditA: { type: 'string' },
          auditB: { type: 'string' },
        },
      },
    },
  }, async (request) => {
    const { auditA, auditB } = request.query as {
      auditA: string;
      auditB: string;
    };

    const [findingsA, findingsB] = await Promise.all([
      db.vulnerability.findMany({
        where: { auditId: auditA },
        include: { contract: true },
      }),
      db.vulnerability.findMany({
        where: { auditId: auditB },
        include: { contract: true },
      }),
    ]);

    // Find common and unique findings
    const titlesA = new Set(findingsA.map((f) => f.title));
    const titlesB = new Set(findingsB.map((f) => f.title));

    const onlyInA = findingsA.filter((f) => !titlesB.has(f.title));
    const onlyInB = findingsB.filter((f) => !titlesA.has(f.title));
    const common = findingsA.filter((f) => titlesB.has(f.title));

    return {
      auditA: {
        id: auditA,
        total: findingsA.length,
        unique: onlyInA.length,
      },
      auditB: {
        id: auditB,
        total: findingsB.length,
        unique: onlyInB.length,
      },
      common: common.length,
      details: {
        onlyInA,
        onlyInB,
        common,
      },
    };
  });
};
