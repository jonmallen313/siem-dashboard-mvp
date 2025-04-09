// frontend/src/components/EventsTable.tsx
import React from 'react';
import { SecurityEvent } from '../api/events';

interface EventsTableProps {
  events: SecurityEvent[];
}

const EventsTable: React.FC<EventsTableProps> = ({ events }) => {
  // Function to format timestamp
  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  // Function to get severity color class
  const getSeverityClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 text-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'low':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Time
            </th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Type
            </th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Source IP
            </th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Destination IP
            </th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Severity
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {events.length > 0 ? (
            events.map((event) => (
              <tr key={event.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {formatTimestamp(event.timestamp)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                  {event.event_type}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {event.source_ip}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {event.destination_ip}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getSeverityClass(event.severity)}`}>
                    {event.severity}
                  </span>
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={5} className="px-6 py-4 text-center text-sm text-gray-500">
                No security events found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default EventsTable;
