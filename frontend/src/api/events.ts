// frontend/src/api/events.ts
export interface SecurityEvent {
  id: number;
  timestamp: string;
  event_type: string;
  source_ip: string;
  destination_ip: string;
  severity: string;
  description: string;
}

export const fetchSecurityEvents = async (): Promise<SecurityEvent[]> => {
  const token = localStorage.getItem('token');
  
  if (!token) {
    throw new Error('Authentication required');
  }
  
  const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/security-events`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
  
  if (!response.ok) {
    throw new Error('Failed to fetch security events');
  }
  
  return response.json();
};

// Add this function to fetch events from Elasticsearch
export const fetchElasticsearchEvents = async (index = 'filebeat-*', size = 100): Promise<any[]> => {
  const token = localStorage.getItem('token');
  
  if (!token) {
    throw new Error('Authentication required');
  }
  
  const response = await fetch(
    `${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/es-security-events?index=${index}&size=${size}`, 
    {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    }
  );
  
  if (!response.ok) {
    throw new Error('Failed to fetch Elasticsearch events');
  }
  
  const data = await response.json();
  return data;
};

// Helper function to transform Elasticsearch events to our SecurityEvent format
export const transformElasticsearchEvents = (esEvents: any[]): SecurityEvent[] => {
  return esEvents.map((hit, index) => {
    const source = hit._source;
    
    return {
      id: index,
      timestamp: source['@timestamp'] || new Date().toISOString(),
      event_type: source.event?.type || source.event?.category || 'Unknown',
      source_ip: source.source?.ip || source.client?.ip || 'Unknown',
      destination_ip: source.destination?.ip || source.server?.ip || 'Unknown',
      severity: source.event?.severity || 'Unknown',
      description: source.message || JSON.stringify(source).substring(0, 100) + '...'
    };
  });
};
