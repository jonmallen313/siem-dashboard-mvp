// frontend/src/pages/DashboardPage.tsx
import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { fetchSecurityEvents, SecurityEvent } from '../api/events';
import Navbar from '../components/Navbar';
import EventsTable from '../components/EventsTable';
import SeverityChart from '../components/SeverityChart';

const DashboardPage: React.FC = () => {
  const { user, logout } = useAuth();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadEvents = async () => {
      try {
        const data = await fetchSecurityEvents();
        setEvents(data);
        setLoading(false);
      } catch (err) {
        setError('Failed to load security events');
        setLoading(false);
      }
    };

    loadEvents();
  }, []);

  // Process data for the severity chart
  const severityData = React.useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    events.forEach(event => {
      counts[event.severity as keyof typeof counts]++;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [events]);

  return (
    <div className="min-h-screen bg-gray-100">
      <Navbar username={user?.username} onLogout={logout} />
      
      <div className="container mx-auto px-4 py-6">
        <h1 className="text-2xl font-bold text-gray-800 mb-6">Security Events Dashboard</h1>
        
        {loading ? (
          <div className="flex justify-center items-center h-64">
            <p className="text-gray-500">Loading security events...</p>
          </div>
        ) : error ? (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded" role="alert">
            <p>{error}</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <div className="bg-white shadow rounded-lg p-6">
                <h2 className="text-lg font-semibold mb-4">Recent Security Events</h2>
                <EventsTable events={events} />
              </div>
            </div>
            
            <div className="lg:col-span-1">
              <div className="bg-white shadow rounded-lg p-6">
                <h2 className="text-lg font-semibold mb-4">Events by Severity</h2>
                <SeverityChart data={severityData} />
              </div>
              
              <div className="bg-white shadow rounded-lg p-6 mt-6">
                <h2 className="text-lg font-semibold mb-4">Summary</h2>
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 bg-blue-50 rounded-lg">
                    <p className="text-sm text-gray-500">Total Events</p>
                    <p className="text-2xl font-bold">{events.length}</p>
                  </div>
                  <div className="p-4 bg-red-50 rounded-lg">
                    <p className="text-sm text-gray-500">Critical Events</p>
                    <p className="text-2xl font-bold text-red-600">{severityData.find(d => d.name === 'Critical')?.value || 0}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DashboardPage;
