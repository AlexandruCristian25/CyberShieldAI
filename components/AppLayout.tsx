// components/AppLayout.tsx
import React, { ReactNode } from "react";

interface AppLayoutProps {
  children: ReactNode;
  className?: string;
}

const AppLayout = React.memo(({ children, className = "" }: AppLayoutProps) => {
  return (
    <main className={`min-h-screen bg-gradient-to-br from-indigo-500 via-purple-600 to-pink-500 text-white font-sans ${className}`}>
      <header className="p-6 flex justify-between items-center bg-black/20 shadow-lg">
        <h1 className="text-2xl font-bold tracking-wide">CyberShield AI</h1>
        <nav className="space-x-4">
          <a href="/dashboard" className="hover:text-yellow-300">Dashboard</a>
          <a href="/upload" className="hover:text-yellow-300">Upload</a>
          <a href="/settings" className="hover:text-yellow-300">Settings</a>
        </nav>
      </header>

      <div className="max-w-5xl mx-auto py-10 px-4">
        {children}
      </div>

      <footer className="text-center text-sm text-gray-300 py-4 bg-black/20 mt-8 rounded-t-xl">
        © {new Date().getFullYear()} CyberShield AI - All rights reserved
      </footer>
    </main>
  );
});

export default AppLayout;
