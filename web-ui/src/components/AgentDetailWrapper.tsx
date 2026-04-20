import React, { useEffect, useState } from 'react';
import { AgentDetail } from './AgentDetail';

export const AgentDetailWrapper: React.FC = () => {
  const [id, setId] = useState<number | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const idParam = params.get('id');
    if (idParam) {
      setId(parseInt(idParam, 10));
    }
  }, []);

  if (id === null) {
    return <div className="p-8 text-center text-gray-500">Loading agent details...</div>;
  }

  return <AgentDetail id={id} />;
};
