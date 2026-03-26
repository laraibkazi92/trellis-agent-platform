import React from 'react';
import type { Agent } from '../lib/api';
import { Cpu, Wrench as ToolIcon, Activity, ExternalLink } from 'lucide-react';

interface AgentCardProps {
  agent: Agent;
}

export const AgentCard: React.FC<AgentCardProps> = ({ agent }) => {
  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'inactive':
        return 'bg-gray-100 text-gray-800';
      case 'error':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-blue-100 text-blue-800';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden hover:shadow-lg transition-shadow">
      <div className="p-5">
        <div className="flex justify-between items-start mb-4">
          <h3 className="text-lg font-semibold text-gray-900">{agent.name}</h3>
          <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(agent.status)}`}>
            {agent.status}
          </span>
        </div>
        
        <div className="space-y-3 mb-5">
          <div className="flex items-center text-sm text-gray-600">
            <Cpu className="w-4 h-4 mr-2 text-indigo-500" />
            <span className="font-medium mr-1">Model:</span> {agent.model_provider}/{agent.model_name}
          </div>
          <div className="flex items-center text-sm text-gray-600">
            <ToolIcon className="w-4 h-4 mr-2 text-indigo-500" />
            <span className="font-medium mr-1">Tools:</span> {agent.tool_count || 0} assigned
          </div>
          <div className="flex items-center text-sm text-gray-600">
            <Activity className="w-4 h-4 mr-2 text-indigo-500" />
            <span className="font-medium mr-1">ID:</span> {agent.id}
          </div>
        </div>

        <div className="flex gap-2">
          <a
            href={`/agents/${agent.id}`}
            className="flex-1 text-center bg-indigo-50 text-indigo-600 hover:bg-indigo-100 px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center justify-center gap-1"
          >
            Manage <ExternalLink className="w-3 h-3" />
          </a>
          <button
            onClick={() => window.open(`/api/v1/chat/completions`, '_blank')}
            className="flex-1 bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 px-4 py-2 rounded-md text-sm font-medium transition-colors"
          >
            Try API
          </button>
        </div>
      </div>
    </div>
  );
};
