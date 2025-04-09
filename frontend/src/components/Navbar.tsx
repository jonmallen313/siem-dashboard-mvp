// frontend/src/components/Navbar.tsx
import React from 'react';

interface NavbarProps {
  username: string | undefined;
  onLogout: () => void;
}

const Navbar: React.FC<NavbarProps> = ({ username, onLogout }) => {
  return (
    <nav className="bg-indigo-600">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <span className="text-white font-bold text-xl">SIEM Dashboard</span>
            </div>
          </div>
          <div className="flex items-center">
            <span className="text-white mr-4">Welcome, {username}</span>
            <button
              onClick={onLogout}
              className="bg-indigo-700 hover:bg-indigo-800 text-white px-3 py-2 rounded-md text-sm font-medium"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;

// frontend/src/components/SeverityChart.tsx
import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

interface DataItem {
  name: string;
  value: number;
}

interface SeverityChartProps {
  data: DataItem[];
}

const COLORS = ['#EF4444', '#F97316', '#FBBF24', '#34D399'];

const SeverityChart: React.FC<SeverityChartProps> = ({ data }) => {
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            labelLine={false}
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SeverityChart;
