// ==================== Core Types ====================

export type ProtocolType = 
  | 'DEX' | 'LENDING' | 'NFT' | 'BRIDGE' 
  | 'STAKING' | 'YIELD' | 'GOVERNANCE' | 'ORACLE' | 'OTHER';

export type Chain = 
  | 'ETHEREUM' | 'BSC' | 'POLYGON' | 'ARBITRUM' 
  | 'OPTIMISM' | 'AVALANCHE' | 'BASE' | 'OTHER';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type VulnCategory = 
  | 'ACCESS_CONTROL' | 'REENTRANCY' | 'ARITHMETIC' | 'LOGIC_ERROR'
  | 'ORACLE_MANIPULATION' | 'TOKEN_HANDLING' | 'EXTERNAL_INTERACTION'
  | 'DATA_VALIDATION' | 'GAS_ISSUE' | 'PROTOCOL_SPECIFIC';

export type DetectionMethod = 
  | 'STATIC_ANALYSIS' | 'PATTERN_MATCH' | 'AI_INFERENCE' | 'FUZZING' | 'MANUAL';

export type ProjectStatus = 
  | 'PENDING' | 'INGESTING' | 'ANALYZING' | 'AUDITING' 
  | 'GENERATING_POC' | 'COMPLETED' | 'FAILED';

export type VulnStatus = 
  | 'DETECTED' | 'VERIFIED' | 'FALSE_POSITIVE' | 'FIXED' | 'ACKNOWLEDGED';

export type AuditStatus = 
  | 'QUEUED' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

// ==================== API Types ====================

export interface CreateAuditRequest {
  githubUrl: string;
  branch?: string;
  commitHash?: string;
  config?: AuditConfig;
}

export interface AuditConfig {
  // Detection settings
  enableStaticAnalysis?: boolean;
  enableAiInference?: boolean;
  enableFuzzing?: boolean;
  
  // Pro Mode - Multi-phase deep analysis like experienced auditor
  proMode?: boolean;
  
  // Scope
  includePatterns?: string[];
  excludePatterns?: string[];
  
  // AI settings
  aiModel?: string;
  maxTokens?: number;
  
  // PoC settings
  generatePoc?: boolean;
  forkBlock?: number;
  rpcUrl?: string;
}

export interface AuditProgress {
  auditId: string;
  status: AuditStatus;
  currentStage: string;
  progress: number; // 0-100
  message?: string;
  findings?: number;
}

// ==================== Analysis Types ====================

export interface ParsedContract {
  filePath: string;
  name: string;
  sourceCode: string;
  ast: SolidityAST;
  imports: ImportInfo[];
  pragmas: PragmaInfo[];
  contracts: ContractDefinition[];
}

export interface SolidityAST {
  nodeType: string;
  src: string;
  nodes: ASTNode[];
  [key: string]: unknown;
}

export interface ASTNode {
  nodeType: string;
  id: number;
  src: string;
  name?: string;
  [key: string]: unknown;
}

export interface ImportInfo {
  path: string;
  absolutePath: string;
  symbolAliases: Array<{ foreign: string; local: string }>;
}

export interface PragmaInfo {
  literals: string[];
}

export interface ContractDefinition {
  name: string;
  kind: 'contract' | 'library' | 'interface' | 'abstract';
  baseContracts: string[];
  functions: FunctionDefinition[];
  stateVariables: StateVariable[];
  events: EventDefinition[];
  modifiers: ModifierDefinition[];
}

export interface FunctionDefinition {
  name: string;
  visibility: 'public' | 'external' | 'internal' | 'private';
  stateMutability: 'pure' | 'view' | 'payable' | 'nonpayable';
  parameters: Parameter[];
  returnParameters: Parameter[];
  modifiers: string[];
  body?: ASTNode;
  startLine: number;
  endLine: number;
}

export interface StateVariable {
  name: string;
  type: string;
  visibility: string;
  constant: boolean;
  immutable: boolean;
}

export interface EventDefinition {
  name: string;
  parameters: Parameter[];
}

export interface ModifierDefinition {
  name: string;
  parameters: Parameter[];
}

export interface Parameter {
  name: string;
  type: string;
  indexed?: boolean;
}

// ==================== Control Flow ====================

export interface ControlFlowGraph {
  nodes: CFGNode[];
  edges: CFGEdge[];
  entryNode: string;
  exitNodes: string[];
}

export interface CFGNode {
  id: string;
  type: 'entry' | 'exit' | 'statement' | 'condition' | 'loop' | 'call';
  code?: string;
  line?: number;
}

export interface CFGEdge {
  from: string;
  to: string;
  condition?: string;
}

// ==================== Vulnerability Detection ====================

export interface VulnerabilityFinding {
  id: string;
  category: VulnCategory;
  severity: Severity;
  title: string;
  description: string;
  location: CodeLocation;
  detectionMethod: DetectionMethod;
  confidence: number;
  codeSnippet?: string;
  remediation?: string;
  references?: string[];
}

export interface CodeLocation {
  filePath: string;
  contractName?: string;
  functionName?: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

// ==================== PoC Types ====================

export interface PoCRequest {
  vulnerability: VulnerabilityFinding;
  contract: ParsedContract;
  projectContext: ProjectContext;
}

export interface PoCResult {
  success: boolean;
  code: string;
  setupCommands: string[];
  executionCommand: string;
  verified: boolean;
  executionLog?: string;
  error?: string;
  estimatedLoss?: string;
}

export interface ProjectContext {
  protocolType?: ProtocolType;
  chains: Chain[];
  dependencies: DependencyInfo[];
  relatedVulnerabilities: KnowledgeBaseMatch[];
}

export interface DependencyInfo {
  name: string;
  version: string;
  source: string;
}

export interface KnowledgeBaseMatch {
  id: string;
  title: string;
  similarity: number;
  category: VulnCategory;
  severity: Severity;
  pocTemplate?: string;
}

// ==================== Knowledge Base Types ====================

export interface KBEntry {
  id: string;
  source: string;
  sourceId?: string;
  sourceUrl?: string;
  title: string;
  description: string;
  category?: VulnCategory;
  severity?: Severity;
  protocolType?: ProtocolType;
  vulnerableCode?: string;
  fixedCode?: string;
  pocCode?: string;
  tags: string[];
  chain?: Chain;
  protocol?: string;
  publishedAt?: Date;
}

export interface KBSearchQuery {
  query: string;
  filters?: {
    category?: VulnCategory[];
    severity?: Severity[];
    source?: string[];
    protocolType?: ProtocolType[];
    chain?: Chain[];
    dateFrom?: Date;
    dateTo?: Date;
  };
  limit?: number;
  offset?: number;
}

export interface KBSearchResult {
  entries: KBEntry[];
  total: number;
  facets?: {
    category: Record<string, number>;
    severity: Record<string, number>;
    source: Record<string, number>;
  };
}

// ==================== Report Types ====================

export interface AuditReport {
  id: string;
  auditId: string;
  projectName: string;
  generatedAt: Date;
  
  summary: ReportSummary;
  findings: ReportFinding[];
  appendix?: ReportAppendix;
}

export interface ReportSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<VulnCategory, number>;
  riskScore: number;
  auditDuration: number;
  coverage: number;
}

export interface ReportFinding {
  id: string;
  severity: Severity;
  category: VulnCategory;
  title: string;
  description: string;
  impact: string;
  location: CodeLocation;
  codeSnippet: string;
  poc?: string;
  remediation: string;
  references: string[];
  status: VulnStatus;
}

export interface ReportAppendix {
  contractList: string[];
  methodology: string;
  toolsUsed: string[];
  disclaimer: string;
}

// ==================== WebSocket Events ====================

export type WSEventType = 
  | 'audit:started'
  | 'audit:progress'
  | 'audit:finding'
  | 'audit:completed'
  | 'audit:failed'
  | 'poc:started'
  | 'poc:completed'
  | 'poc:failed';

export interface WSEvent {
  type: WSEventType;
  auditId: string;
  timestamp: Date;
  data: unknown;
}
