import { db } from '../lib/db.js';
import { config } from '../lib/config.js';
import { createChildLogger } from '../lib/logger.js';
import { GitHubIngestionService } from './github-ingestion.js';
import { SolidityParserService } from './solidity-parser.js';
import { StaticAnalyzer } from './static-analyzer.js';
import { AiAuditor } from './ai-auditor.js';
import { AiAuditorOracle } from './ai-auditor-oracle.js';
import { AiAuditorOpenAI } from './ai-auditor-openai.js';
import { AiAuditorPro } from './ai-auditor-pro.js';
import { PocGenerator } from './poc-generator.js';
import { ReportGenerator } from './report-generator.js';
import {
  emitAuditProgress,
  emitAuditFinding,
  emitAuditCompleted,
  emitAuditFailed,
} from '../api/websocket.js';
import type { AuditConfig, VulnerabilityFinding } from '../types/index.js';

const logger = createChildLogger('audit-orchestrator');

interface CreateAuditInput {
  githubUrl: string;
  branch?: string;
  commitHash?: string;
  config?: AuditConfig;
}

export class AuditOrchestrator {
  private githubService: GitHubIngestionService;
  private parser: SolidityParserService;
  private staticAnalyzer: StaticAnalyzer;
  private aiAuditor: AiAuditor | AiAuditorOracle | AiAuditorOpenAI;
  private pocGenerator: PocGenerator;
  private reportGenerator: ReportGenerator;
  private runningAudits: Map<string, AbortController>;
  private aiProvider: 'anthropic' | 'openai' | 'oracle';

  constructor() {
    this.githubService = new GitHubIngestionService();
    this.parser = new SolidityParserService();
    this.staticAnalyzer = new StaticAnalyzer();
    
    // Determine which AI provider to use
    const openaiApiKey = process.env.OPENAI_API_KEY;
    const anthropicApiKey = config.anthropicApiKey;
    
    if (openaiApiKey) {
      logger.info('Using OpenAI API for AI analysis');
      this.aiAuditor = new AiAuditorOpenAI(openaiApiKey);
      this.aiProvider = 'openai';
    } else if (anthropicApiKey) {
      logger.info('Using Anthropic API for AI analysis');
      this.aiAuditor = new AiAuditor();
      this.aiProvider = 'anthropic';
    } else {
      logger.info('Using Oracle CLI for AI analysis (no API key configured)');
      this.aiAuditor = new AiAuditorOracle();
      this.aiProvider = 'oracle';
    }
    
    this.pocGenerator = new PocGenerator();
    this.reportGenerator = new ReportGenerator();
    this.runningAudits = new Map();
  }

  async createAudit(input: CreateAuditInput) {
    const { githubUrl, branch = 'main', commitHash, config = {} } = input;

    logger.info({ githubUrl, branch }, 'Creating new audit');

    // Create or find project
    let project = await db.project.findFirst({
      where: { githubUrl },
    });

    if (!project) {
      project = await db.project.create({
        data: {
          githubUrl,
          name: this.extractProjectName(githubUrl),
          branch,
          commitHash,
        },
      });
    }

    // Create audit
    const audit = await db.audit.create({
      data: {
        projectId: project.id,
        config: config as any,
        status: 'QUEUED',
      },
    });

    // Start audit in background
    this.runAudit(audit.id, project.id, config).catch((error) => {
      logger.error({ error, auditId: audit.id }, 'Audit failed');
    });

    return {
      id: audit.id,
      projectId: project.id,
      status: audit.status,
      message: 'Audit created and queued for processing',
    };
  }

  async runAudit(auditId: string, projectId: string, config: AuditConfig) {
    const abortController = new AbortController();
    this.runningAudits.set(auditId, abortController);

    try {
      // Update status
      await db.audit.update({
        where: { id: auditId },
        data: { status: 'IN_PROGRESS', startedAt: new Date() },
      });

      const project = await db.project.findUnique({
        where: { id: projectId },
      });

      if (!project) {
        throw new Error('Project not found');
      }

      // Stage 1: Ingest code from GitHub
      emitAuditProgress(auditId, 'ingestion', 10, 'Cloning repository...');
      const projectPath = await this.githubService.cloneRepository(
        project.githubUrl,
        project.branch,
        project.commitHash || undefined
      );

      if (abortController.signal.aborted) return;

      // Stage 2: Parse Solidity files
      emitAuditProgress(auditId, 'parsing', 25, 'Parsing contracts...');
      const contracts = await this.parser.parseProject(projectPath);
      
      // Save contracts to database
      for (const contract of contracts) {
        await db.contract.upsert({
          where: {
            projectId_filePath: {
              projectId,
              filePath: contract.filePath,
            },
          },
          create: {
            projectId,
            filePath: contract.filePath,
            name: contract.name,
            sourceCode: contract.sourceCode,
            ast: contract.ast as any,
            lines: contract.sourceCode.split('\n').length,
          },
          update: {
            sourceCode: contract.sourceCode,
            ast: contract.ast as any,
            lines: contract.sourceCode.split('\n').length,
          },
        });
      }

      // Update project stats
      await db.project.update({
        where: { id: projectId },
        data: {
          totalContracts: contracts.length,
          totalLines: contracts.reduce(
            (sum, c) => sum + c.sourceCode.split('\n').length,
            0
          ),
          protocolType: await this.detectProtocolType(contracts),
        },
      });

      if (abortController.signal.aborted) return;

      // Stage 3: Static Analysis
      emitAuditProgress(auditId, 'static_analysis', 40, 'Running static analysis...');
      const staticFindings = config.enableStaticAnalysis !== false
        ? await this.staticAnalyzer.analyze(projectPath)
        : [];

      if (abortController.signal.aborted) return;

      // Stage 4: AI Analysis
      let aiFindings: VulnerabilityFinding[] = [];
      if (config.enableAiInference !== false) {
        if (config.proMode) {
          // Use Pro auditor for deep multi-phase analysis
          emitAuditProgress(auditId, 'ai_analysis', 60, 'Running Pro AI analysis (5 phases)...');
          const openaiKey = process.env.OPENAI_API_KEY;
          if (openaiKey) {
            const proAuditor = new AiAuditorPro(openaiKey);
            aiFindings = await proAuditor.analyze(contracts, project);
          } else {
            logger.warn('Pro mode requires OPENAI_API_KEY');
            aiFindings = await this.aiAuditor.analyze(contracts, project);
          }
        } else {
          emitAuditProgress(auditId, 'ai_analysis', 60, 'Running AI analysis...');
          aiFindings = await this.aiAuditor.analyze(contracts, project);
        }
      }

      if (abortController.signal.aborted) return;

      // Combine and deduplicate findings
      const allFindings = this.deduplicateFindings([...staticFindings, ...aiFindings]);

      // Save findings to database
      for (const finding of allFindings) {
        const contract = await db.contract.findFirst({
          where: { projectId, filePath: finding.location.filePath },
        });

        const vuln = await db.vulnerability.create({
          data: {
            auditId,
            contractId: contract?.id,
            category: finding.category,
            severity: finding.severity,
            title: finding.title,
            description: finding.description,
            filePath: finding.location.filePath,
            startLine: finding.location.startLine,
            endLine: finding.location.endLine,
            codeSnippet: finding.codeSnippet,
            detectionMethod: finding.detectionMethod,
            confidence: finding.confidence,
            remediation: finding.remediation,
            references: finding.references || [],
          },
        });

        emitAuditFinding(auditId, {
          id: vuln.id,
          severity: vuln.severity,
          title: vuln.title,
          category: vuln.category,
        });
      }

      if (abortController.signal.aborted) return;

      // Stage 5: Generate PoCs
      if (config.generatePoc !== false) {
        emitAuditProgress(auditId, 'poc_generation', 80, 'Generating PoCs...');
        
        const vulnerabilities = await db.vulnerability.findMany({
          where: { 
            auditId,
            severity: { in: ['CRITICAL', 'HIGH'] },
          },
        });

        for (const vuln of vulnerabilities) {
          try {
            const poc = await this.pocGenerator.generate(vuln, contracts, project);
            
            if (poc.success) {
              await db.proofOfConcept.create({
                data: {
                  vulnerabilityId: vuln.id,
                  code: poc.code,
                  setupCommands: poc.setupCommands,
                  executionCmd: poc.executionCommand,
                  verified: poc.verified,
                  executionLog: poc.executionLog,
                  estimatedLoss: poc.estimatedLoss,
                },
              });
            }
          } catch (error) {
            logger.warn({ error, vulnId: vuln.id }, 'Failed to generate PoC');
          }
        }
      }

      // Update audit completion
      const summary = await this.calculateAuditSummary(auditId);
      
      await db.audit.update({
        where: { id: auditId },
        data: {
          status: 'COMPLETED',
          completedAt: new Date(),
          duration: Math.floor(
            (Date.now() - (await db.audit.findUnique({ where: { id: auditId } }))!.startedAt!.getTime()) / 1000
          ),
          ...summary,
        },
      });

      emitAuditProgress(auditId, 'completed', 100, 'Audit completed');
      emitAuditCompleted(auditId, summary);

      logger.info({ auditId, findings: summary.totalFindings }, 'Audit completed successfully');

    } catch (error) {
      logger.error({ error, auditId }, 'Audit failed');
      
      await db.audit.update({
        where: { id: auditId },
        data: { status: 'FAILED' },
      });

      emitAuditFailed(auditId, error instanceof Error ? error.message : 'Unknown error');
      throw error;
    } finally {
      this.runningAudits.delete(auditId);
    }
  }

  async cancelAudit(auditId: string) {
    const controller = this.runningAudits.get(auditId);
    if (controller) {
      controller.abort();
      this.runningAudits.delete(auditId);
    }
  }

  async generatePoc(auditId: string, findingId: string) {
    const vulnerability = await db.vulnerability.findUnique({
      where: { id: findingId },
      include: {
        contract: true,
        audit: { include: { project: true } },
      },
    });

    if (!vulnerability) {
      throw new Error('Vulnerability not found');
    }

    const contracts = await db.contract.findMany({
      where: { projectId: vulnerability.audit.projectId },
    });

    const parsedContracts = contracts.map((c) => ({
      filePath: c.filePath,
      name: c.name,
      sourceCode: c.sourceCode,
      ast: c.ast as any,
      imports: [],
      pragmas: [],
      contracts: [],
    }));

    const poc = await this.pocGenerator.generate(
      vulnerability,
      parsedContracts,
      vulnerability.audit.project
    );

    if (poc.success) {
      await db.proofOfConcept.upsert({
        where: { vulnerabilityId: findingId },
        create: {
          vulnerabilityId: findingId,
          code: poc.code,
          setupCommands: poc.setupCommands,
          executionCmd: poc.executionCommand,
          verified: poc.verified,
          executionLog: poc.executionLog,
          estimatedLoss: poc.estimatedLoss,
        },
        update: {
          code: poc.code,
          verified: poc.verified,
          executionLog: poc.executionLog,
        },
      });
    }

    return poc;
  }

  async generateReport(auditId: string, format: string) {
    const audit = await db.audit.findUnique({
      where: { id: auditId },
      include: {
        project: true,
        vulnerabilities: {
          include: { poc: true, contract: true },
          orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
        },
      },
    });

    if (!audit) {
      throw new Error('Audit not found');
    }

    const report = await this.reportGenerator.generate(audit, format);

    await db.report.create({
      data: {
        auditId,
        format,
        content: report.content,
        filePath: report.filePath,
      },
    });

    return report;
  }

  private extractProjectName(githubUrl: string): string {
    const match = githubUrl.match(/github\.com\/([^/]+\/[^/]+)/);
    return match ? match[1] : 'unknown';
  }

  private async detectProtocolType(contracts: any[]): Promise<any> {
    // Simple heuristic based on contract names and imports
    const allCode = contracts.map((c) => c.sourceCode).join('\n').toLowerCase();

    if (allCode.includes('swap') || allCode.includes('amm') || allCode.includes('liquidity')) {
      return 'DEX';
    }
    if (allCode.includes('lend') || allCode.includes('borrow') || allCode.includes('collateral')) {
      return 'LENDING';
    }
    if (allCode.includes('erc721') || allCode.includes('erc1155') || allCode.includes('nft')) {
      return 'NFT';
    }
    if (allCode.includes('bridge') || allCode.includes('crosschain')) {
      return 'BRIDGE';
    }
    if (allCode.includes('stake') || allCode.includes('reward')) {
      return 'STAKING';
    }
    if (allCode.includes('vault') || allCode.includes('yield') || allCode.includes('strategy')) {
      return 'YIELD';
    }
    if (allCode.includes('governor') || allCode.includes('vote') || allCode.includes('proposal')) {
      return 'GOVERNANCE';
    }

    return 'OTHER';
  }

  private deduplicateFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
    const seen = new Map<string, VulnerabilityFinding>();

    for (const finding of findings) {
      const key = `${finding.location.filePath}:${finding.location.startLine}:${finding.category}`;
      const existing = seen.get(key);

      if (!existing || finding.confidence > existing.confidence) {
        seen.set(key, finding);
      }
    }

    return Array.from(seen.values());
  }

  private async calculateAuditSummary(auditId: string) {
    const findings = await db.vulnerability.groupBy({
      by: ['severity'],
      where: { auditId },
      _count: true,
    });

    const counts = {
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
    };

    for (const f of findings) {
      counts.totalFindings += f._count;
      switch (f.severity) {
        case 'CRITICAL':
          counts.criticalCount = f._count;
          break;
        case 'HIGH':
          counts.highCount = f._count;
          break;
        case 'MEDIUM':
          counts.mediumCount = f._count;
          break;
        case 'LOW':
          counts.lowCount = f._count;
          break;
        case 'INFO':
          counts.infoCount = f._count;
          break;
      }
    }

    return counts;
  }
}
