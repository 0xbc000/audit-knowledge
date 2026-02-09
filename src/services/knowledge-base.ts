import { db } from '../lib/db.js';
import { config } from '../lib/config.js';
import { createChildLogger } from '../lib/logger.js';
import type { KBSearchQuery, KBSearchResult, VulnCategory, Severity } from '../types/index.js';

const logger = createChildLogger('knowledge-base');

export class KnowledgeBaseService {
  private qdrantClient: any = null;

  constructor() {
    this.initQdrant();
  }

  private async initQdrant() {
    try {
      const { QdrantClient } = await import('@qdrant/js-client-rest');
      this.qdrantClient = new QdrantClient({
        url: config.qdrantUrl,
      });
      
      // Ensure collection exists
      await this.ensureCollection();
    } catch (error) {
      logger.warn({ error }, 'Qdrant client initialization failed, using database-only search');
    }
  }

  private async ensureCollection() {
    if (!this.qdrantClient) return;

    try {
      const collections = await this.qdrantClient.getCollections();
      const exists = collections.collections.some(
        (c: any) => c.name === 'vulnerabilities'
      );

      if (!exists) {
        await this.qdrantClient.createCollection('vulnerabilities', {
          vectors: {
            size: 1536, // OpenAI embedding size
            distance: 'Cosine',
          },
        });
        logger.info('Created Qdrant collection: vulnerabilities');
      }
    } catch (error) {
      logger.error({ error }, 'Failed to ensure Qdrant collection');
    }
  }

  async search(query: KBSearchQuery): Promise<KBSearchResult> {
    const { query: searchText, filters, limit = 20, offset = 0 } = query;

    // Build database query
    const where: any = {};

    if (filters?.category?.length) {
      where.category = { in: filters.category };
    }
    if (filters?.severity?.length) {
      where.severity = { in: filters.severity };
    }
    if (filters?.source?.length) {
      where.source = { in: filters.source };
    }
    if (filters?.protocolType?.length) {
      where.protocolType = { in: filters.protocolType };
    }
    if (filters?.chain?.length) {
      where.chain = { in: filters.chain };
    }
    if (filters?.dateFrom || filters?.dateTo) {
      where.publishedAt = {};
      if (filters.dateFrom) {
        where.publishedAt.gte = new Date(filters.dateFrom);
      }
      if (filters.dateTo) {
        where.publishedAt.lte = new Date(filters.dateTo);
      }
    }

    // Full-text search on title and description
    if (searchText) {
      where.OR = [
        { title: { contains: searchText, mode: 'insensitive' } },
        { description: { contains: searchText, mode: 'insensitive' } },
        { tags: { has: searchText.toLowerCase() } },
      ];
    }

    const [entries, total] = await Promise.all([
      db.knowledgeBaseEntry.findMany({
        where,
        orderBy: [
          { severity: 'asc' },
          { publishedAt: 'desc' },
        ],
        take: limit,
        skip: offset,
      }),
      db.knowledgeBaseEntry.count({ where }),
    ]);

    // Get facets
    const [categoryFacets, severityFacets, sourceFacets] = await Promise.all([
      db.knowledgeBaseEntry.groupBy({
        by: ['category'],
        where: searchText ? { OR: where.OR } : {},
        _count: true,
      }),
      db.knowledgeBaseEntry.groupBy({
        by: ['severity'],
        where: searchText ? { OR: where.OR } : {},
        _count: true,
      }),
      db.knowledgeBaseEntry.groupBy({
        by: ['source'],
        where: searchText ? { OR: where.OR } : {},
        _count: true,
      }),
    ]);

    return {
      entries: entries.map(this.mapEntry),
      total,
      facets: {
        category: Object.fromEntries(
          categoryFacets.map((f) => [f.category || 'unknown', f._count])
        ),
        severity: Object.fromEntries(
          severityFacets.map((f) => [f.severity || 'unknown', f._count])
        ),
        source: Object.fromEntries(
          sourceFacets.map((f) => [f.source, f._count])
        ),
      },
    };
  }

  async semanticSearch(query: string, limit: number = 10): Promise<any[]> {
    // If Qdrant is not available, fall back to database search
    if (!this.qdrantClient) {
      const results = await this.search({ query, limit });
      return results.entries;
    }

    try {
      // Generate embedding for query
      const embedding = await this.generateEmbedding(query);

      // Search in Qdrant
      const results = await this.qdrantClient.search('vulnerabilities', {
        vector: embedding,
        limit,
        with_payload: true,
      });

      // Get full entries from database
      const ids = results.map((r: any) => r.payload.entryId);
      const entries = await db.knowledgeBaseEntry.findMany({
        where: { id: { in: ids } },
      });

      // Sort by search result order
      return ids.map((id: string) => 
        entries.find((e) => e.id === id)
      ).filter(Boolean).map(this.mapEntry);

    } catch (error) {
      logger.error({ error }, 'Semantic search failed, falling back to database');
      const results = await this.search({ query, limit });
      return results.entries;
    }
  }

  async findSimilar(entryId: string, limit: number = 5): Promise<any[]> {
    const entry = await db.knowledgeBaseEntry.findUnique({
      where: { id: entryId },
    });

    if (!entry) {
      return [];
    }

    // Find by same category and similar tags
    const similar = await db.knowledgeBaseEntry.findMany({
      where: {
        id: { not: entryId },
        OR: [
          { category: entry.category },
          { tags: { hasSome: entry.tags } },
        ],
      },
      orderBy: { publishedAt: 'desc' },
      take: limit,
    });

    return similar.map(this.mapEntry);
  }

  async findSimilarPocs(category: VulnCategory, title: string): Promise<any[]> {
    // Search for entries with PoC code
    const entries = await db.knowledgeBaseEntry.findMany({
      where: {
        category,
        pocCode: { not: null },
      },
      orderBy: { publishedAt: 'desc' },
      take: 5,
    });

    return entries.map(this.mapEntry);
  }

  async addEntry(entry: any): Promise<string> {
    const created = await db.knowledgeBaseEntry.create({
      data: {
        source: entry.source,
        sourceId: entry.sourceId,
        sourceUrl: entry.sourceUrl,
        title: entry.title,
        description: entry.description,
        category: entry.category,
        severity: entry.severity,
        protocolType: entry.protocolType,
        vulnerableCode: entry.vulnerableCode,
        fixedCode: entry.fixedCode,
        pocCode: entry.pocCode,
        tags: entry.tags || [],
        chain: entry.chain,
        protocol: entry.protocol,
        publishedAt: entry.publishedAt,
      },
    });

    // Generate and store embedding
    if (this.qdrantClient) {
      try {
        const text = `${entry.title}\n${entry.description}`;
        const embedding = await this.generateEmbedding(text);

        await this.qdrantClient.upsert('vulnerabilities', {
          points: [
            {
              id: created.id,
              vector: embedding,
              payload: {
                entryId: created.id,
                title: entry.title,
                category: entry.category,
                severity: entry.severity,
              },
            },
          ],
        });
      } catch (error) {
        logger.warn({ error }, 'Failed to store embedding');
      }
    }

    return created.id;
  }

  async addPattern(pattern: any): Promise<string> {
    const created = await db.vulnerabilityPattern.create({
      data: {
        category: pattern.category,
        subcategory: pattern.subcategory,
        severity: pattern.severity,
        name: pattern.name,
        description: pattern.description,
        astPatterns: pattern.astPatterns || [],
        codePatterns: pattern.codePatterns || [],
        semanticRules: pattern.semanticRules || [],
        pocTemplate: pattern.pocTemplate,
        remediation: pattern.remediation,
        references: pattern.references || [],
        source: pattern.source,
        sourceUrl: pattern.sourceUrl,
      },
    });

    return created.id;
  }

  async getPatterns(category?: VulnCategory): Promise<any[]> {
    const patterns = await db.vulnerabilityPattern.findMany({
      where: category ? { category } : {},
      orderBy: { severity: 'asc' },
    });

    return patterns;
  }

  private async generateEmbedding(text: string): Promise<number[]> {
    // Use OpenAI embeddings if available
    if (config.openaiApiKey) {
      try {
        const response = await fetch('https://api.openai.com/v1/embeddings', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${config.openaiApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'text-embedding-3-small',
            input: text.substring(0, 8000),
          }),
        });

        const data = await response.json();
        return data.data[0].embedding;
      } catch (error) {
        logger.error({ error }, 'Failed to generate OpenAI embedding');
      }
    }

    // Fallback: return zero vector (semantic search won't work well)
    return new Array(1536).fill(0);
  }

  private mapEntry(entry: any) {
    return {
      id: entry.id,
      source: entry.source,
      sourceId: entry.sourceId,
      sourceUrl: entry.sourceUrl,
      title: entry.title,
      description: entry.description,
      category: entry.category,
      severity: entry.severity,
      protocolType: entry.protocolType,
      vulnerableCode: entry.vulnerableCode,
      fixedCode: entry.fixedCode,
      pocCode: entry.pocCode,
      tags: entry.tags,
      chain: entry.chain,
      protocol: entry.protocol,
      publishedAt: entry.publishedAt,
      createdAt: entry.createdAt,
    };
  }
}
