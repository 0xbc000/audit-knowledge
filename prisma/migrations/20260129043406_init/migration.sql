-- CreateEnum
CREATE TYPE "ProtocolType" AS ENUM ('DEX', 'LENDING', 'NFT', 'BRIDGE', 'STAKING', 'YIELD', 'GOVERNANCE', 'ORACLE', 'OTHER');

-- CreateEnum
CREATE TYPE "Chain" AS ENUM ('ETHEREUM', 'BSC', 'POLYGON', 'ARBITRUM', 'OPTIMISM', 'AVALANCHE', 'BASE', 'OTHER');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- CreateEnum
CREATE TYPE "VulnCategory" AS ENUM ('ACCESS_CONTROL', 'REENTRANCY', 'ARITHMETIC', 'LOGIC_ERROR', 'ORACLE_MANIPULATION', 'TOKEN_HANDLING', 'EXTERNAL_INTERACTION', 'DATA_VALIDATION', 'GAS_ISSUE', 'PROTOCOL_SPECIFIC');

-- CreateEnum
CREATE TYPE "DetectionMethod" AS ENUM ('STATIC_ANALYSIS', 'PATTERN_MATCH', 'AI_INFERENCE', 'FUZZING', 'MANUAL');

-- CreateEnum
CREATE TYPE "ProjectStatus" AS ENUM ('PENDING', 'INGESTING', 'ANALYZING', 'AUDITING', 'GENERATING_POC', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "VulnStatus" AS ENUM ('DETECTED', 'VERIFIED', 'FALSE_POSITIVE', 'FIXED', 'ACKNOWLEDGED');

-- CreateEnum
CREATE TYPE "AuditStatus" AS ENUM ('QUEUED', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED');

-- CreateTable
CREATE TABLE "Project" (
    "id" TEXT NOT NULL,
    "githubUrl" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT,
    "commitHash" TEXT,
    "branch" TEXT NOT NULL DEFAULT 'main',
    "protocolType" "ProtocolType",
    "chains" "Chain"[],
    "description" TEXT,
    "totalContracts" INTEGER NOT NULL DEFAULT 0,
    "totalLines" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Project_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Contract" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "filePath" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "sourceCode" TEXT NOT NULL,
    "bytecode" TEXT,
    "ast" JSONB,
    "cfg" JSONB,
    "lines" INTEGER NOT NULL DEFAULT 0,
    "complexity" INTEGER NOT NULL DEFAULT 0,
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Contract_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Function" (
    "id" TEXT NOT NULL,
    "contractId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "visibility" TEXT NOT NULL,
    "stateMutability" TEXT,
    "signature" TEXT NOT NULL,
    "startLine" INTEGER NOT NULL,
    "endLine" INTEGER NOT NULL,
    "parameters" JSONB NOT NULL DEFAULT '[]',
    "returnTypes" JSONB NOT NULL DEFAULT '[]',
    "modifiers" TEXT[],
    "externalCalls" JSONB NOT NULL DEFAULT '[]',
    "stateChanges" JSONB NOT NULL DEFAULT '[]',
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,

    CONSTRAINT "Function_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Dependency" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "source" TEXT NOT NULL,

    CONSTRAINT "Dependency_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Audit" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "status" "AuditStatus" NOT NULL DEFAULT 'QUEUED',
    "config" JSONB NOT NULL DEFAULT '{}',
    "currentStage" TEXT,
    "progress" INTEGER NOT NULL DEFAULT 0,
    "totalFindings" INTEGER NOT NULL DEFAULT 0,
    "criticalCount" INTEGER NOT NULL DEFAULT 0,
    "highCount" INTEGER NOT NULL DEFAULT 0,
    "mediumCount" INTEGER NOT NULL DEFAULT 0,
    "lowCount" INTEGER NOT NULL DEFAULT 0,
    "infoCount" INTEGER NOT NULL DEFAULT 0,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "duration" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Audit_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Vulnerability" (
    "id" TEXT NOT NULL,
    "auditId" TEXT NOT NULL,
    "contractId" TEXT,
    "category" "VulnCategory" NOT NULL,
    "severity" "Severity" NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "filePath" TEXT,
    "startLine" INTEGER,
    "endLine" INTEGER,
    "codeSnippet" TEXT,
    "detectionMethod" "DetectionMethod" NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "status" "VulnStatus" NOT NULL DEFAULT 'DETECTED',
    "remediation" TEXT,
    "references" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Vulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProofOfConcept" (
    "id" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "setupCommands" TEXT[],
    "executionCmd" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "executionLog" TEXT,
    "expectedResult" TEXT,
    "actualResult" TEXT,
    "estimatedLoss" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProofOfConcept_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "auditId" TEXT NOT NULL,
    "format" TEXT NOT NULL,
    "content" TEXT,
    "filePath" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VulnerabilityPattern" (
    "id" TEXT NOT NULL,
    "category" "VulnCategory" NOT NULL,
    "subcategory" TEXT,
    "severity" "Severity" NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "astPatterns" JSONB NOT NULL DEFAULT '[]',
    "codePatterns" JSONB NOT NULL DEFAULT '[]',
    "semanticRules" JSONB NOT NULL DEFAULT '[]',
    "pocTemplate" TEXT,
    "remediation" TEXT,
    "references" TEXT[],
    "source" TEXT,
    "sourceUrl" TEXT,
    "embeddingId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VulnerabilityPattern_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KnowledgeBaseEntry" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "sourceId" TEXT,
    "sourceUrl" TEXT,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" "VulnCategory",
    "severity" "Severity",
    "protocolType" "ProtocolType",
    "vulnerableCode" TEXT,
    "fixedCode" TEXT,
    "pocCode" TEXT,
    "tags" TEXT[],
    "chain" "Chain",
    "protocol" TEXT,
    "embeddingId" TEXT,
    "publishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KnowledgeBaseEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Project_githubUrl_idx" ON "Project"("githubUrl");

-- CreateIndex
CREATE INDEX "Project_protocolType_idx" ON "Project"("protocolType");

-- CreateIndex
CREATE INDEX "Contract_projectId_idx" ON "Contract"("projectId");

-- CreateIndex
CREATE INDEX "Contract_name_idx" ON "Contract"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Contract_projectId_filePath_key" ON "Contract"("projectId", "filePath");

-- CreateIndex
CREATE INDEX "Function_contractId_idx" ON "Function"("contractId");

-- CreateIndex
CREATE INDEX "Function_name_idx" ON "Function"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Dependency_projectId_name_key" ON "Dependency"("projectId", "name");

-- CreateIndex
CREATE INDEX "Audit_projectId_idx" ON "Audit"("projectId");

-- CreateIndex
CREATE INDEX "Audit_status_idx" ON "Audit"("status");

-- CreateIndex
CREATE INDEX "Audit_createdAt_idx" ON "Audit"("createdAt");

-- CreateIndex
CREATE INDEX "Vulnerability_auditId_idx" ON "Vulnerability"("auditId");

-- CreateIndex
CREATE INDEX "Vulnerability_severity_idx" ON "Vulnerability"("severity");

-- CreateIndex
CREATE INDEX "Vulnerability_category_idx" ON "Vulnerability"("category");

-- CreateIndex
CREATE INDEX "Vulnerability_status_idx" ON "Vulnerability"("status");

-- CreateIndex
CREATE UNIQUE INDEX "ProofOfConcept_vulnerabilityId_key" ON "ProofOfConcept"("vulnerabilityId");

-- CreateIndex
CREATE INDEX "Report_auditId_idx" ON "Report"("auditId");

-- CreateIndex
CREATE INDEX "VulnerabilityPattern_category_idx" ON "VulnerabilityPattern"("category");

-- CreateIndex
CREATE INDEX "VulnerabilityPattern_severity_idx" ON "VulnerabilityPattern"("severity");

-- CreateIndex
CREATE INDEX "VulnerabilityPattern_source_idx" ON "VulnerabilityPattern"("source");

-- CreateIndex
CREATE INDEX "KnowledgeBaseEntry_source_idx" ON "KnowledgeBaseEntry"("source");

-- CreateIndex
CREATE INDEX "KnowledgeBaseEntry_category_idx" ON "KnowledgeBaseEntry"("category");

-- CreateIndex
CREATE INDEX "KnowledgeBaseEntry_severity_idx" ON "KnowledgeBaseEntry"("severity");

-- CreateIndex
CREATE INDEX "KnowledgeBaseEntry_protocolType_idx" ON "KnowledgeBaseEntry"("protocolType");

-- CreateIndex
CREATE UNIQUE INDEX "KnowledgeBaseEntry_source_sourceId_key" ON "KnowledgeBaseEntry"("source", "sourceId");

-- AddForeignKey
ALTER TABLE "Contract" ADD CONSTRAINT "Contract_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Function" ADD CONSTRAINT "Function_contractId_fkey" FOREIGN KEY ("contractId") REFERENCES "Contract"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Dependency" ADD CONSTRAINT "Dependency_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Audit" ADD CONSTRAINT "Audit_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vulnerability" ADD CONSTRAINT "Vulnerability_auditId_fkey" FOREIGN KEY ("auditId") REFERENCES "Audit"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vulnerability" ADD CONSTRAINT "Vulnerability_contractId_fkey" FOREIGN KEY ("contractId") REFERENCES "Contract"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProofOfConcept" ADD CONSTRAINT "ProofOfConcept_vulnerabilityId_fkey" FOREIGN KEY ("vulnerabilityId") REFERENCES "Vulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_auditId_fkey" FOREIGN KEY ("auditId") REFERENCES "Audit"("id") ON DELETE CASCADE ON UPDATE CASCADE;
