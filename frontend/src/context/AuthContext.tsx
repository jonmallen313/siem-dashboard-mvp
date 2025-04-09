// frontend/src/context/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { loginUser } from '../api/auth';

interface AuthContextType {
  isAuthenticated: boolean;
  user: any;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  user: null,
  login: async () => false,
  logout: () => {},
  loading: true,
});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('token');
    if (token) {
      setIsAuthenticated(true);
      // In a real app, you'd validate the token here
      setUser({ username: localStorage.getItem('username') });
    }
    setLoading(false);
  }, []);

  const login = async (username: string, password: string) => {
    try {
      const { token } = await loginUser(username, password);
      localStorage.setItem('token', token);
      localStorage.setItem('username', username);
      setIsAuthenticated(true);
      setUser({ username });
      return true;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setIsAuthenticated(false);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};
