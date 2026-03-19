import React from 'react';
import Sidebar from './Sidebar';
import Header from './Header';
import { useApp } from '../App';

export default function Layout({ children }) {
  const { sidebarCollapsed } = useApp();

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div
        className={`flex flex-col flex-1 overflow-hidden transition-all duration-300 ${
          sidebarCollapsed ? 'ml-16' : 'ml-64'
        }`}
      >
        <Header />
        <main className="flex-1 overflow-y-auto p-6 bg-dark-950">
          <div className="animate-fade-in">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
