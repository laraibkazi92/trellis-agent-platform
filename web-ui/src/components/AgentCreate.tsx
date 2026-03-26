import React, { useEffect, useState } from 'react';
import { getTools, createAgent, type Tool } from '../lib/api';
import { Check, ChevronRight, Save, X, Cpu, Wrench as ToolIcon } from 'lucide-react';

export const AgentCreate: React.FC = () => {
  const [tools, setTools] = useState<Tool[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  
  const [formData, setFormData] = useState({
    name: '',
    model_provider: 'openai',
    model_name: 'gpt-4o',
    system_prompt: '',
    docker_container_name: '',
    status: 'inactive',
    assigned_tool_ids: [] as number[]
  });

  useEffect(() => {
    const fetchTools = async () => {
      try {
        const data = await getTools();
        setTools(data);
      } catch (err) {
        console.error('Failed to fetch tools', err);
      } finally {
        setLoading(false);
      }
    };
    fetchTools();
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const toggleTool = (id: number) => {
    setFormData(prev => {
      const current = [...prev.assigned_tool_ids];
      if (current.includes(id)) {
        return { ...prev, assigned_tool_ids: current.filter(tid => tid !== id) };
      } else {
        return { ...prev, assigned_tool_ids: [...current, id] };
      }
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      // Auto-generate container name if empty
      const finalData = {
        ...formData,
        docker_container_name: formData.docker_container_name || `${formData.name.toLowerCase().replace(/\s+/g, '-')}-1`
      };
      await createAgent(finalData);
      window.location.href = '/';
    } catch (err) {
      alert('Failed to create agent. Check console for details.');
      console.error(err);
      setSaving(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center gap-2 mb-6 text-sm text-gray-500">
        <a href="/" className="hover:text-indigo-600">Marketplace</a>
        <ChevronRight className="w-4 h-4" />
        <span className="text-gray-900 font-medium">Create New Agent</span>
      </div>

      <form onSubmit={handleSubmit} className="space-y-8">
        <div className="bg-white shadow-sm border border-gray-200 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-2 bg-gray-50/50">
            <Cpu className="w-5 h-5 text-indigo-600" />
            <h2 className="text-lg font-semibold text-gray-900">Basic Information</h2>
          </div>
          <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Agent Name</label>
              <input
                type="text"
                name="name"
                required
                placeholder="e.g. Finance Agent"
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 outline-none"
                value={formData.name}
                onChange={handleInputChange}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Model Provider</label>
              <select
                name="model_provider"
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 outline-none bg-white"
                value={formData.model_provider}
                onChange={handleInputChange}
              >
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="gemini">Google Gemini</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Model Name</label>
              <input
                type="text"
                name="model_name"
                required
                placeholder="e.g. gpt-4o"
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 outline-none"
                value={formData.model_name}
                onChange={handleInputChange}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Docker Container Name (Optional)</label>
              <input
                type="text"
                name="docker_container_name"
                placeholder="Auto-generated if empty"
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 outline-none"
                value={formData.docker_container_name}
                onChange={handleInputChange}
              />
            </div>
            <div className="col-span-1 md:col-span-2 space-y-2">
              <label className="text-sm font-medium text-gray-700">System Prompt</label>
              <textarea
                name="system_prompt"
                rows={4}
                required
                placeholder="Describe the agent's personality and instructions..."
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 outline-none"
                value={formData.system_prompt}
                onChange={handleInputChange}
              />
            </div>
          </div>
        </div>

        <div className="bg-white shadow-sm border border-gray-200 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-2 bg-gray-50/50">
            <ToolIcon className="w-5 h-5 text-indigo-600" />
            <h2 className="text-lg font-semibold text-gray-900">Assign Tools</h2>
          </div>
          <div className="p-6">
            {loading ? (
              <div className="text-center py-10 text-gray-500">Loading available tools...</div>
            ) : tools.length === 0 ? (
              <div className="text-center py-10 bg-gray-50 rounded-lg border border-dashed border-gray-300 text-gray-500">
                No tools registered. Register tools using the CLI first.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {tools.map(tool => (
                  <div
                    key={tool.id}
                    onClick={() => toggleTool(tool.id)}
                    className={`cursor-pointer p-4 rounded-lg border-2 transition-all flex items-start gap-3 ${
                      formData.assigned_tool_ids.includes(tool.id)
                        ? 'border-indigo-500 bg-indigo-50'
                        : 'border-gray-100 hover:border-gray-200 bg-white'
                    }`}
                  >
                    <div className={`mt-1 flex-shrink-0 w-5 h-5 rounded-full border flex items-center justify-center ${
                      formData.assigned_tool_ids.includes(tool.id)
                        ? 'bg-indigo-600 border-indigo-600 text-white'
                        : 'border-gray-300 bg-white text-transparent'
                    }`}>
                      <Check className="w-3 h-3" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold text-gray-900">{tool.name}</div>
                      <div className="text-xs text-gray-500 line-clamp-2">{tool.description}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="flex justify-end gap-4">
          <button
            type="button"
            onClick={() => window.location.href = '/'}
            className="px-6 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saving}
            className={`px-8 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors flex items-center gap-2 ${saving ? 'opacity-70 cursor-not-allowed' : ''}`}
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving...' : 'Create Agent'}
          </button>
        </div>
      </form>
    </div>
  );
};
