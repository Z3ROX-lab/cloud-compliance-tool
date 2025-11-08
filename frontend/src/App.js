import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import AuditRunner from './components/AuditRunner';
import ComplianceResults from './components/ComplianceResults';
import ArchitectureView from './components/ArchitectureView';
import Reports from './components/Reports';

function Navigation() {
  const location = useLocation();

  const navItems = [
    { path: '/', label: 'Dashboard', icon: '📊' },
    { path: '/audit', label: 'Lancer Audit', icon: '🔍' },
    { path: '/results', label: 'Résultats', icon: '📋' },
    { path: '/architecture', label: 'Architecture', icon: '🏗️' },
    { path: '/reports', label: 'Rapports', icon: '📄' },
  ];

  return (
    <nav className="bg-gradient-to-r from-blue-600 to-blue-800 text-white shadow-lg">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center space-x-8">
            <div className="flex-shrink-0 flex items-center space-x-2">
              <span className="text-2xl">🛡️</span>
              <span className="font-bold text-xl">Cloud Compliance Tool</span>
            </div>
            <div className="flex space-x-4">
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    location.pathname === item.path
                      ? 'bg-blue-700 text-white'
                      : 'text-blue-100 hover:bg-blue-700 hover:text-white'
                  }`}
                >
                  <span className="mr-1">{item.icon}</span>
                  {item.label}
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        <Navigation />
        <main className="max-w-7xl mx-auto py-6 px-4">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/audit" element={<AuditRunner />} />
            <Route path="/results" element={<ComplianceResults />} />
            <Route path="/architecture" element={<ArchitectureView />} />
            <Route path="/reports" element={<Reports />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
