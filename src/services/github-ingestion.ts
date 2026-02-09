import simpleGit, { SimpleGit } from 'simple-git';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { createChildLogger } from '../lib/logger.js';
import { config } from '../lib/config.js';

const logger = createChildLogger('github-ingestion');

export class GitHubIngestionService {
  private git: SimpleGit;
  private workDir: string;

  constructor() {
    this.git = simpleGit();
    this.workDir = path.join(os.tmpdir(), 'sca-repos');
  }

  async cloneRepository(
    githubUrl: string,
    branch: string = 'main',
    commitHash?: string
  ): Promise<string> {
    logger.info({ githubUrl, branch, commitHash }, 'Cloning repository');

    // Create work directory if it doesn't exist
    await fs.mkdir(this.workDir, { recursive: true });

    // Extract repo name for local path
    const repoName = this.extractRepoName(githubUrl);
    const localPath = path.join(this.workDir, `${repoName}-${Date.now()}`);

    // Prepare clone options
    const cloneOptions: string[] = ['--depth', '1'];
    if (branch) {
      cloneOptions.push('--branch', branch);
    }

    // Add token for private repos if available
    let cloneUrl = githubUrl;
    if (config.githubToken && githubUrl.startsWith('https://github.com')) {
      cloneUrl = githubUrl.replace(
        'https://github.com',
        `https://${config.githubToken}@github.com`
      );
    }

    try {
      // Clone the repository
      await this.git.clone(cloneUrl, localPath, cloneOptions);
      logger.info({ localPath }, 'Repository cloned');

      // Checkout specific commit if provided
      if (commitHash) {
        const repoGit = simpleGit(localPath);
        await repoGit.fetch(['--unshallow']).catch(() => {
          // Repository might already be fully fetched
        });
        await repoGit.checkout(commitHash);
        logger.info({ commitHash }, 'Checked out specific commit');
      }

      // Install dependencies if needed
      await this.installDependencies(localPath);

      return localPath;
    } catch (error) {
      logger.error({ error, githubUrl }, 'Failed to clone repository');
      throw error;
    }
  }

  async installDependencies(projectPath: string): Promise<void> {
    logger.info({ projectPath }, 'Installing dependencies');

    // Check for foundry project (foundry.toml)
    const foundryToml = path.join(projectPath, 'foundry.toml');
    if (await this.fileExists(foundryToml)) {
      logger.info('Detected Foundry project, running forge install');
      try {
        const { execSync } = await import('child_process');
        execSync('forge install', {
          cwd: projectPath,
          stdio: 'pipe',
          timeout: 120000,
        });
      } catch (error) {
        logger.warn({ error }, 'Failed to run forge install');
      }
    }

    // Check for hardhat project (hardhat.config.js/ts)
    const hardhatConfigJs = path.join(projectPath, 'hardhat.config.js');
    const hardhatConfigTs = path.join(projectPath, 'hardhat.config.ts');
    if (
      (await this.fileExists(hardhatConfigJs)) ||
      (await this.fileExists(hardhatConfigTs))
    ) {
      logger.info('Detected Hardhat project, running npm install');
      try {
        const { execSync } = await import('child_process');
        
        // Check for yarn.lock or package-lock.json
        const yarnLock = path.join(projectPath, 'yarn.lock');
        const npmLock = path.join(projectPath, 'package-lock.json');
        
        if (await this.fileExists(yarnLock)) {
          execSync('yarn install', {
            cwd: projectPath,
            stdio: 'pipe',
            timeout: 300000,
          });
        } else {
          execSync('npm install', {
            cwd: projectPath,
            stdio: 'pipe',
            timeout: 300000,
          });
        }
      } catch (error) {
        logger.warn({ error }, 'Failed to install npm dependencies');
      }
    }
  }

  async findSolidityFiles(projectPath: string): Promise<string[]> {
    const { glob } = await import('glob');
    
    // Common patterns for Solidity files
    const patterns = [
      'contracts/**/*.sol',
      'src/**/*.sol',
      '*.sol',
    ];

    // Exclude patterns
    const ignore = [
      '**/node_modules/**',
      '**/lib/**',
      '**/test/**',
      '**/tests/**',
      '**/mock/**',
      '**/mocks/**',
      '**/*.t.sol',
      '**/*.s.sol',
    ];

    const files: string[] = [];

    for (const pattern of patterns) {
      const matches = await glob(pattern, {
        cwd: projectPath,
        ignore,
        nodir: true,
      });
      files.push(...matches.map((f) => path.join(projectPath, f)));
    }

    // Deduplicate
    return [...new Set(files)];
  }

  async readFile(filePath: string): Promise<string> {
    return fs.readFile(filePath, 'utf-8');
  }

  async cleanup(projectPath: string): Promise<void> {
    try {
      await fs.rm(projectPath, { recursive: true, force: true });
      logger.info({ projectPath }, 'Cleaned up project directory');
    } catch (error) {
      logger.warn({ error, projectPath }, 'Failed to cleanup project directory');
    }
  }

  private extractRepoName(githubUrl: string): string {
    const match = githubUrl.match(/github\.com\/([^/]+)\/([^/.]+)/);
    if (match) {
      return `${match[1]}-${match[2]}`;
    }
    return 'unknown-repo';
  }

  private async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }
}
