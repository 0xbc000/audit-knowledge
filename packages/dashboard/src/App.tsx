import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { 
  LayoutDashboard, 
  Shield, 
  Database, 
  FolderCode,
  Plus,
  Menu,
  X
} from 'lucide-react';
import { Dashboard } from './pages/Dashboard';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30000,
      refetchOnWindowFocus: false,
    },
  },
});

type Page = 'dashboard' | 'audits' | 'knowledge-base' | 'projects' | 'new-audit';

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'audits', label: 'Audits', icon: Shield },
  { id: 'knowledge-base', label: 'Knowledge Base', icon: Database },
  { id: 'projects', label: 'Projects', icon: FolderCode },
];

function App() {
  const [currentPage, setCurrentPage] = useState<Page>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <QueryClientProvider client={queryClient}>
      <div className="flex h-screen bg-gray-50">
        {/* Sidebar */}
        <aside className={`${sidebarOpen ? 'w-64' : 'w-16'} bg-gray-900 text-white transition-all duration-300 flex flex-col`}>
          {/* Logo */}
          <div className="p-4 flex items-center justify-between border-b border-gray-800">
            {sidebarOpen && (
              <div className="flex items-center gap-2">
                <Shield className="w-8 h-8 text-blue-400" />
                <span className="font-bold text-lg">SC Auditor</span>
              </div>
            )}
            <button 
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 rounded-lg hover:bg-gray-800"
            >
              {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-4 space-y-2">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id as Page)}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                  currentPage === item.id 
                    ? 'bg-blue-600 text-white' 
                    : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <item.icon className="w-5 h-5 flex-shrink-0" />
                {sidebarOpen && <span>{item.label}</span>}
              </button>
            ))}
          </nav>

          {/* New Audit Button */}
          <div className="p-4 border-t border-gray-800">
            <button
              onClick={() => setCurrentPage('new-audit')}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
            >
              <Plus className="w-5 h-5" />
              {sidebarOpen && <span>New Audit</span>}
            </button>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-auto">
          {currentPage === 'dashboard' && <Dashboard />}
          {currentPage === 'audits' && <AuditsPage />}
          {currentPage === 'knowledge-base' && <KnowledgeBasePage />}
          {currentPage === 'projects' && <ProjectsPage />}
          {currentPage === 'new-audit' && <NewAuditPage onComplete={() => setCurrentPage('audits')} />}
        </main>
      </div>
    </QueryClientProvider>
  );
}

// Placeholder pages
function AuditsPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Audits</h1>
      <div className="card">
        <p className="text-gray-500">Audit list will be displayed here.</p>
      </div>
    </div>
  );
}

function KnowledgeBasePage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Knowledge Base</h1>
      <div className="card">
        <p className="text-gray-500">Browse 49,000+ vulnerability patterns.</p>
      </div>
    </div>
  );
}

function ProjectsPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Projects</h1>
      <div className="card">
        <p className="text-gray-500">Your audited projects will appear here.</p>
      </div>
    </div>
  );
}

function NewAuditPage({ onComplete }: { onComplete: () => void }) {
  const [githubUrl, setGithubUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch('http://localhost:3000/api/v1/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ githubUrl }),
      });

      if (!response.ok) throw new Error('Failed to create audit');
      
      onComplete();
    } catch (err) {
      setError('Failed to create audit. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">New Audit</h1>
      
      <form onSubmit={handleSubmit} className="card space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            GitHub Repository URL
          </label>
          <input
            type="url"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            required
          />
        </div>

        {error && (
          <div className="text-red-600 text-sm">{error}</div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Creating Audit...' : 'Start Audit'}
        </button>
      </form>
    </div>
  );
}

export default App;
