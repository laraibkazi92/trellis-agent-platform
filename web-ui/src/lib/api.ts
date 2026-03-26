import axios from 'axios';

const API_BASE_URL = import.meta.env.PUBLIC_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
});

export interface Tool {
  id: number;
  name: string;
  description?: string;
  tool_directory: string;
  entry_point_module: string;
  entry_point_function: string;
  etcd_secret_key?: string;
  etcd_secret_key_reference: boolean;
  is_active: boolean;
}

export interface Agent {
  id: number;
  name: string;
  model_provider: string;
  model_name: string;
  status: string;
  tool_count?: number;
  tags?: string[];
}

export interface AgentConfig {
  agent: {
    id: number;
    name: string;
    model_provider: string;
    model_name: string;
    system_prompt: string;
  };
  assigned_tools: Tool[];
}

export const getAgents = async () => {
  const response = await api.get('/marketplace/agents');
  return response.data.agents as Agent[];
};

export const getTools = async () => {
  const response = await api.get('/marketplace/tools');
  return response.data.tools as Tool[];
};

export const getAgentConfig = async (id: number) => {
  const response = await api.get(`/agents/${id}/config`);
  return response.data as AgentConfig;
};

export const createAgent = async (data: any) => {
  const response = await api.post('/marketplace/agents', data);
  return response.data;
};

export const checkAgentHealth = async (id: number) => {
  const response = await api.get(`/agents/${id}/health`);
  return response.data;
};

export const listCredentials = async (prefix: string = '') => {
  const response = await api.get(`/marketplace/credentials?prefix=${prefix}`);
  return response.data.credentials as string[];
};

export const createCredential = async (data: any) => {
  const response = await api.post('/marketplace/credentials', data);
  return response.data;
};
