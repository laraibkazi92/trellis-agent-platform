import React, { useEffect, useState } from 'react';
import { listCredentials, createCredential } from '../lib/api';
import { Key, RefreshCw, Plus, Save, X, Search, Lock } from 'lucide-react';

export const CredentialList: React.FC = () => {
  const [credentials, setCredentials] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [newCred, setNewCred] = useState({ path: '', value: '' });
  const [saving, setSaving] = useState(false);

  const fetchCredentials = async () => {
    setLoading(true);
    try {
      const data = await listCredentials();
      setCredentials(data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch credentials. Is etcd accessible via Control Plane?');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCredentials();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      let parsedValue;
      try {
        parsedValue = JSON.parse(newCred.value);
      } catch (e) {
        // If not JSON, treat as plain string
        parsedValue = { key: newCred.value };
      }
      
      await createCredential({
        path: newCred.path,
        value: parsedValue
      });
      
      setNewCred({ path: '', value: '' });
      setIsAdding(false);
      fetchCredentials();
    } catch (err) {
      alert('Failed to save credential');
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  const filteredCredentials = credentials.filter(path => 
    path.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Secrets Management</h1>
          <p className="text-gray-500">Manage tool and provider credentials in etcd</p>
        </div>
        <div className="flex gap-2 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search keys..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 outline-none"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <button 
            onClick={fetchCredentials}
            className="p-2 border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
          >
            <RefreshCw className={`w-5 h-5 text-gray-600 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setIsAdding(true)}
            className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 transition-colors flex items-center gap-2"
          >
            <Plus className="w-5 h-5" />
            Add Secret
          </button>
        </div>
      </div>

      {isAdding && (
        <div className="bg-white p-6 rounded-lg border border-indigo-200 shadow-sm animate-in fade-in slide-in-from-top-4">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Add New Secret</h3>
            <button onClick={() => setIsAdding(false)} className="text-gray-400 hover:text-gray-600">
              <X className="w-5 h-5" />
            </button>
          </div>
          <form onSubmit={handleSave} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-gray-500 uppercase">Path</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. tools/slack/credentials"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 outline-none"
                  value={newCred.path}
                  onChange={e => setNewCred({...newCred, path: e.target.value})}
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-gray-500 uppercase">Value (JSON or String)</label>
                <input
                  type="text"
                  required
                  placeholder='e.g. {"token": "xoxb-..."}'
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 outline-none"
                  value={newCred.value}
                  onChange={e => setNewCred({...newCred, value: e.target.value})}
                />
              </div>
            </div>
            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setIsAdding(false)}
                className="px-4 py-2 text-gray-600 hover:text-gray-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="bg-indigo-600 text-white px-6 py-2 rounded-md hover:bg-indigo-700 transition-colors flex items-center gap-2"
              >
                <Save className="w-4 h-4" />
                {saving ? 'Saving...' : 'Save Secret'}
              </button>
            </div>
          </form>
        </div>
      )}

      {loading && credentials.length === 0 ? (
        <div className="flex justify-center py-20">
          <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin" />
        </div>
      ) : error ? (
        <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md">
          {error}
        </div>
      ) : filteredCredentials.length === 0 ? (
        <div className="bg-white rounded-lg border border-dashed border-gray-300 p-20 text-center text-gray-500">
          No secrets found matching your search.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredCredentials.map(path => (
            <div key={path} className="bg-white p-4 rounded-lg border border-gray-200 flex items-center gap-4 hover:border-indigo-300 transition-colors group">
              <div className="w-10 h-10 rounded-full bg-gray-50 flex items-center justify-center text-gray-400 group-hover:bg-indigo-50 group-hover:text-indigo-500 transition-colors">
                <Lock className="w-5 h-5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-bold text-gray-400 uppercase tracking-wider truncate">Path</div>
                <div className="text-sm font-medium text-gray-900 truncate" title={path}>{path}</div>
              </div>
              <div className="text-indigo-400 opacity-0 group-hover:opacity-100 transition-opacity">
                <Key className="w-4 h-4" />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
