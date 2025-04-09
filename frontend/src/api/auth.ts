// frontend/src/api/auth.ts
export const loginUser = async (username: string, password: string) => {
  const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      'username': username,
      'password': password,
    }),
  });

  if (!response.ok) {
    throw new Error('Login failed');
  }

  const data = await response.json();
  return { token: data.access_token };
};

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
