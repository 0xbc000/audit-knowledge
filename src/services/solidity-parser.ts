import { promises as fs } from 'fs';
import path from 'path';
import { createChildLogger } from '../lib/logger.js';
import type { ParsedContract, SolidityAST } from '../types/index.js';

const logger = createChildLogger('solidity-parser');

export class SolidityParserService {
  async parseProject(projectPath: string): Promise<ParsedContract[]> {
    logger.info({ projectPath }, 'Parsing Solidity project');

    const solidityFiles = await this.findSolidityFiles(projectPath);
    logger.info({ fileCount: solidityFiles.length }, 'Found Solidity files');

    const contracts: ParsedContract[] = [];

    for (const filePath of solidityFiles) {
      try {
        const contract = await this.parseFile(filePath, projectPath);
        if (contract) {
          contracts.push(contract);
        }
      } catch (error) {
        logger.warn({ error, filePath }, 'Failed to parse file');
      }
    }

    return contracts;
  }

  async parseFile(filePath: string, projectPath: string): Promise<ParsedContract | null> {
    const sourceCode = await fs.readFile(filePath, 'utf-8');
    const relativePath = path.relative(projectPath, filePath);

    try {
      // Use solc to compile and get AST
      const ast = await this.compileToAST(filePath, sourceCode, projectPath);

      // Extract contract name from AST or filename
      const contractName = this.extractContractName(ast, filePath);

      return {
        filePath: relativePath,
        name: contractName,
        sourceCode,
        ast,
        imports: this.extractImports(ast),
        pragmas: this.extractPragmas(ast),
        contracts: this.extractContractDefinitions(ast),
      };
    } catch (error) {
      logger.warn({ error, filePath }, 'AST compilation failed, using basic parsing');

      // Fallback to basic parsing
      return {
        filePath: relativePath,
        name: this.extractContractNameFromSource(sourceCode, filePath),
        sourceCode,
        ast: { nodeType: 'SourceUnit', src: '', nodes: [] },
        imports: this.extractImportsBasic(sourceCode),
        pragmas: this.extractPragmasBasic(sourceCode),
        contracts: [],
      };
    }
  }

  private async compileToAST(
    filePath: string,
    sourceCode: string,
    projectPath: string
  ): Promise<SolidityAST> {
    // For now, we'll use a simplified AST parsing approach
    // In production, this would use solc-js or slither

    const { execSync } = await import('child_process');

    try {
      // Try using solc if available
      const result = execSync(
        `solc --ast-compact-json "${filePath}" 2>/dev/null || echo "{}"`,
        {
          cwd: projectPath,
          encoding: 'utf-8',
          timeout: 30000,
        }
      );

      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
    } catch (error) {
      // Solc not available or failed
    }

    // Try using forge/foundry
    try {
      const result = execSync(
        `forge build --ast 2>/dev/null`,
        {
          cwd: projectPath,
          encoding: 'utf-8',
          timeout: 60000,
        }
      );
      // Parse AST from forge output if available
    } catch (error) {
      // Forge not available or failed
    }

    // Return basic AST structure
    return this.parseBasicAST(sourceCode);
  }

  private parseBasicAST(sourceCode: string): SolidityAST {
    const nodes: any[] = [];
    const lines = sourceCode.split('\n');

    // Extract contract definitions
    const contractRegex = /^(contract|library|interface|abstract\s+contract)\s+(\w+)/gm;
    let match;

    while ((match = contractRegex.exec(sourceCode)) !== null) {
      const lineNumber = sourceCode.substring(0, match.index).split('\n').length;
      nodes.push({
        nodeType: 'ContractDefinition',
        name: match[2],
        contractKind: match[1].replace('abstract ', ''),
        linearizedBaseContracts: [],
        baseContracts: [],
        src: `${match.index}:${match[0].length}:0`,
      });
    }

    // Extract function definitions
    const functionRegex = /function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private)?\s*(view|pure|payable)?/g;
    while ((match = functionRegex.exec(sourceCode)) !== null) {
      const lineNumber = sourceCode.substring(0, match.index).split('\n').length;
      nodes.push({
        nodeType: 'FunctionDefinition',
        name: match[1],
        visibility: match[3] || 'public',
        stateMutability: match[4] || 'nonpayable',
        parameters: this.parseParameters(match[2]),
        src: `${match.index}:${match[0].length}:0`,
      });
    }

    return {
      nodeType: 'SourceUnit',
      src: `0:${sourceCode.length}:0`,
      nodes,
    };
  }

  private parseParameters(paramsString: string): any[] {
    if (!paramsString.trim()) return [];

    return paramsString.split(',').map((param) => {
      const parts = param.trim().split(/\s+/);
      return {
        type: parts[0],
        name: parts[parts.length - 1],
      };
    });
  }

  private async findSolidityFiles(projectPath: string): Promise<string[]> {
    const { glob } = await import('glob');

    const patterns = ['contracts/**/*.sol', 'src/**/*.sol', '*.sol'];
    const ignore = [
      '**/node_modules/**',
      '**/lib/**',
      '**/*.t.sol',
      '**/*.s.sol',
    ];

    const files: string[] = [];

    for (const pattern of patterns) {
      const matches = await glob(pattern, {
        cwd: projectPath,
        ignore,
        nodir: true,
        absolute: true,
      });
      files.push(...matches);
    }

    return [...new Set(files)];
  }

  private extractContractName(ast: SolidityAST, filePath: string): string {
    const contractNode = ast.nodes?.find(
      (n) => n.nodeType === 'ContractDefinition'
    );
    if (contractNode?.name) {
      return contractNode.name;
    }
    return path.basename(filePath, '.sol');
  }

  private extractContractNameFromSource(sourceCode: string, filePath: string): string {
    const match = sourceCode.match(/^(contract|library|interface)\s+(\w+)/m);
    if (match) {
      return match[2];
    }
    return path.basename(filePath, '.sol');
  }

  private extractImports(ast: SolidityAST): any[] {
    return ast.nodes
      ?.filter((n) => n.nodeType === 'ImportDirective')
      .map((n: any) => ({
        path: n.absolutePath || n.file,
        absolutePath: n.absolutePath,
        symbolAliases: n.symbolAliases || [],
      })) || [];
  }

  private extractImportsBasic(sourceCode: string): any[] {
    const imports: any[] = [];
    const importRegex = /import\s+(?:{[^}]+}\s+from\s+)?["']([^"']+)["']/g;
    let match;

    while ((match = importRegex.exec(sourceCode)) !== null) {
      imports.push({
        path: match[1],
        absolutePath: match[1],
        symbolAliases: [],
      });
    }

    return imports;
  }

  private extractPragmas(ast: SolidityAST): any[] {
    return ast.nodes
      ?.filter((n) => n.nodeType === 'PragmaDirective')
      .map((n: any) => ({
        literals: n.literals || [],
      })) || [];
  }

  private extractPragmasBasic(sourceCode: string): any[] {
    const pragmas: any[] = [];
    const pragmaRegex = /pragma\s+(\w+)\s+([^;]+);/g;
    let match;

    while ((match = pragmaRegex.exec(sourceCode)) !== null) {
      pragmas.push({
        literals: [match[1], match[2]],
      });
    }

    return pragmas;
  }

  private extractContractDefinitions(ast: SolidityAST): any[] {
    return ast.nodes
      ?.filter((n) => n.nodeType === 'ContractDefinition')
      .map((n: any) => ({
        name: n.name,
        kind: n.contractKind || 'contract',
        baseContracts: n.baseContracts?.map((b: any) => b.baseName?.name) || [],
        functions: this.extractFunctions(n),
        stateVariables: this.extractStateVariables(n),
        events: [],
        modifiers: [],
      })) || [];
  }

  private extractFunctions(contractNode: any): any[] {
    if (!contractNode.nodes) return [];

    return contractNode.nodes
      .filter((n: any) => n.nodeType === 'FunctionDefinition')
      .map((n: any) => ({
        name: n.name || (n.kind === 'constructor' ? 'constructor' : 'fallback'),
        visibility: n.visibility || 'public',
        stateMutability: n.stateMutability || 'nonpayable',
        parameters: n.parameters?.parameters || [],
        returnParameters: n.returnParameters?.parameters || [],
        modifiers: n.modifiers?.map((m: any) => m.modifierName?.name) || [],
        startLine: 0,
        endLine: 0,
      }));
  }

  private extractStateVariables(contractNode: any): any[] {
    if (!contractNode.nodes) return [];

    return contractNode.nodes
      .filter((n: any) => n.nodeType === 'VariableDeclaration')
      .map((n: any) => ({
        name: n.name,
        type: n.typeName?.name || n.typeName?.typeDescriptions?.typeString || 'unknown',
        visibility: n.visibility || 'internal',
        constant: n.constant || false,
        immutable: n.mutability === 'immutable',
      }));
  }
}
