import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3000/api/v1';

export const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Types
export interface DashboardStats {
  totalProjects: number;
  totalAudits: number;
  activeAudits: number;
  totalFindings: number;
  criticalFindings: number;
  verifiedPocs: number;
  pocSuccessRate: number;
}

export interface Audit {
  id: string;
  projectId: string;
  status: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  createdAt: string;
  completedAt?: string;
  project?: {
    name: string;
    githubUrl: string;
  };
}

export interface Finding {
  id: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  codeSnippet?: string;
  remediation?: string;
  status: string;
  confidence: number;
  poc?: {
    verified: boolean;
    code: string;
  };
}

export interface KBEntry {
  id: string;
  title: string;
  description: string;
  category?: string;
  severity?: string;
  source: string;
  tags: string[];
  createdAt: string;
}

// API functions
export const dashboardApi = {
  getOverview: () => api.get<{
    stats: DashboardStats;
    recentAudits: Audit[];
    charts: {
      findingsBySeverity: Record<string, number>;
      findingsByCategory: Record<string, number>;
    };
  }>('/dashboard/overview'),
  
  getTrends: (period: string) => api.get(`/dashboard/trends?period=${period}`),
  getAccuracy: () => api.get('/dashboard/accuracy'),
  getActivity: (limit: number) => api.get(`/dashboard/activity?limit=${limit}`),
};

export const auditApi = {
  create: (githubUrl: string, config?: object) => 
    api.post('/audit', { githubUrl, config }),
  
  get: (id: string) => api.get<Audit>(`/audit/${id}`),
  list: (params?: { status?: string; limit?: number; offset?: number }) =>
    api.get<{ audits: Audit[]; total: number }>('/audit', { params }),
  
  getFindings: (id: string, params?: { severity?: string; category?: string }) =>
    api.get<Finding[]>(`/audit/${id}/findings`, { params }),
  
  generateReport: (id: string, format: string) =>
    api.post(`/audit/${id}/report`, { format }),
  
  cancel: (id: string) => api.post(`/audit/${id}/cancel`),
};

export const kbApi = {
  search: (params: {
    query?: string;
    category?: string;
    severity?: string;
    limit?: number;
    offset?: number;
  }) => api.get<{ entries: KBEntry[]; total: number }>('/kb/search', { params }),
  
  getStats: () => api.get('/kb/stats'),
  getCategories: () => api.get('/kb/categories'),
  getEntry: (id: string) => api.get(`/kb/entry/${id}`),
};

export const projectApi = {
  list: (params?: { limit?: number; offset?: number }) =>
    api.get('/project', { params }),
  get: (id: string) => api.get(`/project/${id}`),
  getContracts: (id: string) => api.get(`/project/${id}/contracts`),
};
