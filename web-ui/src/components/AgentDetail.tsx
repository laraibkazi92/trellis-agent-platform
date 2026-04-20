import React, { useEffect, useState } from 'react';
import { getAgentConfig, getTools, assignAgentTools, checkAgentHealth, type AgentConfig, type Tool } from '../lib/api';
import { Cpu, Wrench as ToolIcon, Activity, CheckCircle, XCircle, Loader2, Save, ArrowLeft } from 'lucide-react';

interface AgentDetailProps {
  id: number;
}

export const AgentDetail: React.FC<AgentDetailProps> = ({ id }) => {
  const [config, setConfig] = useState<AgentConfig | null>(null);
  const [allTools, setAllTools] = useState<Tool[]>([]);
  const [assignedToolIds, setAssignedToolIds] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [healthStatus, setHealthStatus] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  
  const [savingTools, setSavingTools] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const [configData, toolsData] = await Promise.all([
          getAgentConfig(id),
          getTools()
        ]);
        setConfig(configData);
        setAllTools(toolsData);
        setAssignedToolIds(new Set(configData.assigned_tools.map(t => t.id)));
      } catch (err: any) {
        console.error(err);
        setError(err.response?.data?.detail || 'Failed to load agent configuration');
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, [id]);

  const handleHealthCheck = async () => {
    setHealthLoading(true);
    try {
      const result = await checkAgentHealth(id);
      setHealthStatus(result.status);
    } catch (err: any) {
      console.error(err);
      setHealthStatus('unhealthy');
    } finally {
      setHealthLoading(false);
    }
  };

  const handleToolToggle = (toolId: number) => {
    setAssignedToolIds(prev => {
      const newSet = new Set(prev);
      if (newSet.has(toolId)) {
        newSet.delete(toolId);
      } else {
        newSet.add(toolId);
      }
      return newSet;
    });
  };

  const handleSaveTools = async () => {
    setSavingTools(true);
    setSaveMessage(null);
    try {
      await assignAgentTools(id, Array.from(assignedToolIds));
      setSaveMessage('Tools assigned successfully');
      setTimeout(() => setSaveMessage(null), 3000);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to assign tools');
    } finally {
      setSavingTools(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center py-20">
        <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
      </div>
    );
  }

  if (error || !config) {
    return (
      <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md">
        {error || 'Agent not found'}
      </div>
    );
  }

  const agent = config.agent;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4 mb-6">
        <a href="/" className="p-2 border border-gray-300 rounded-md hover:bg-gray-50 transition-colors">
          <ArrowLeft className="w-5 h-5 text-gray-600" />
        </a>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{agent.name}</h1>
          <p className="text-gray-500">Manage agent configuration and assigned tools</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration Panel */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
              <h3 className="text-lg font-medium text-gray-900 flex items-center">
                <Cpu className="w-5 h-5 mr-2 text-indigo-500" />
                Configuration
              </h3>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-500 mb-1">Model Provider</label>
                <div className="text-sm text-gray-900 bg-gray-50 px-3 py-2 rounded border border-gray-200 capitalize">
                  {agent.model_provider}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500 mb-1">Model Name</label>
                <div className="text-sm text-gray-900 bg-gray-50 px-3 py-2 rounded border border-gray-200">
                  {agent.model_name}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500 mb-1">System Prompt</label>
                <div className="text-sm text-gray-900 bg-gray-50 px-3 py-2 rounded border border-gray-200 max-h-48 overflow-y-auto whitespace-pre-wrap">
                  {agent.system_prompt || 'No system prompt configured'}
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
              <h3 className="text-lg font-medium text-gray-900 flex items-center">
                <Activity className="w-5 h-5 mr-2 text-indigo-500" />
                Health Status
              </h3>
            </div>
            <div className="p-5 flex flex-col items-center justify-center space-y-4">
              {healthStatus ? (
                <div className={`flex flex-col items-center justify-center p-4 rounded-full w-24 h-24 ${healthStatus === 'healthy' ? 'bg-green-100' : 'bg-red-100'}`}>
                  {healthStatus === 'healthy' ? (
                    <CheckCircle className="w-10 h-10 text-green-600 mb-1" />
                  ) : (
                    <XCircle className="w-10 h-10 text-red-600 mb-1" />
                  )}
                  <span className={`text-xs font-bold uppercase ${healthStatus === 'healthy' ? 'text-green-700' : 'text-red-700'}`}>
                    {healthStatus}
                  </span>
                </div>
              ) : (
                <div className="text-gray-400 text-sm text-center">Status unknown. Click check to test connection.</div>
              )}
              
              <button
                onClick={handleHealthCheck}
                disabled={healthLoading}
                className="w-full bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 px-4 py-2 rounded-md text-sm font-medium transition-colors flex justify-center items-center"
              >
                {healthLoading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
                {healthLoading ? 'Checking...' : 'Check Health'}
              </button>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
             <div className="px-5 py-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
              <h3 className="text-lg font-medium text-gray-900">API Endpoint</h3>
            </div>
            <div className="p-5">
              <div className="bg-gray-900 rounded p-3 text-xs text-gray-300 font-mono overflow-x-auto">
                POST /api/v1/chat/completions<br/>
                <br/>
                &#123;<br/>
                &nbsp;&nbsp;"model": "{agent.name}",<br/>
                &nbsp;&nbsp;"messages": [<br/>
                &nbsp;&nbsp;&nbsp;&nbsp;&#123;"role": "user", "content": "Hello"&#125;<br/>
                &nbsp;&nbsp;]<br/>
                &#125;
              </div>
            </div>
          </div>
        </div>

        {/* Tool Management Panel */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
              <h3 className="text-lg font-medium text-gray-900 flex items-center">
                <ToolIcon className="w-5 h-5 mr-2 text-indigo-500" />
                Assigned Tools
              </h3>
              <button
                onClick={handleSaveTools}
                disabled={savingTools}
                className="bg-indigo-600 text-white px-4 py-2 rounded-md text-sm hover:bg-indigo-700 transition-colors flex items-center"
              >
                {savingTools ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
                Save Changes
              </button>
            </div>
            
            {saveMessage && (
              <div className="bg-green-50 border-b border-green-200 text-green-700 p-3 text-sm px-5 flex items-center">
                <CheckCircle className="w-4 h-4 mr-2" />
                {saveMessage}
              </div>
            )}
            
            <div className="p-0">
              {allTools.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  No tools available in the marketplace. <a href="/tools" className="text-indigo-600 hover:underline">Register tools</a> first.
                </div>
              ) : (
                <ul className="divide-y divide-gray-200 max-h-[600px] overflow-y-auto">
                  {allTools.map(tool => (
                    <li key={tool.id} className="p-4 hover:bg-gray-50 transition-colors">
                      <div className="flex items-start">
                        <div className="flex-shrink-0 mt-0.5">
                          <input
                            type="checkbox"
                            className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded cursor-pointer"
                            checked={assignedToolIds.has(tool.id)}
                            onChange={() => handleToolToggle(tool.id)}
                            id={`tool-${tool.id}`}
                          />
                        </div>
                        <div className="ml-3 flex-1">
                          <label htmlFor={`tool-${tool.id}`} className="cursor-pointer block">
                            <span className="text-sm font-medium text-gray-900">{tool.name}</span>
                            <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
                              {tool.entry_point_module}:{tool.entry_point_function}
                            </span>
                            {tool.description && (
                              <p className="text-sm text-gray-500 mt-1">{tool.description}</p>
                            )}
                          </label>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};