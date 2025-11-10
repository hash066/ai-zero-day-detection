import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  AlertTriangle,
  Monitor,
  Activity,
  Brain,
  Settings,
  Menu,
  X,
  Shield,
} from 'lucide-react';
import { cn } from '../lib/utils';

interface LayoutProps {
  children: React.ReactNode;
  currentPage: string;
  onNavigate: (page: string) => void;
}

const navigation = [
  { name: 'Dashboard', icon: LayoutDashboard, id: 'dashboard' },
  { name: 'Threats', icon: AlertTriangle, id: 'alerts' },
  { name: 'Devices', icon: Monitor, id: 'devices' },
  { name: 'Network', icon: Activity, id: 'network' },
  { name: 'AI Models', icon: Brain, id: 'models' },
];

export function Layout({ children, currentPage, onNavigate }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-dark-950">
      {/* Sidebar for desktop */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
        <div className="flex flex-col flex-1 border-r border-dark-800 bg-dark-900">
          {/* Logo */}
          <div className="flex items-center gap-3 h-16 px-6 border-b border-dark-800">
            <div className="p-2 bg-primary-600 rounded-lg">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-dark-50">Aegis Zero</h1>
              <p className="text-xs text-dark-400">Zero-Day Detection</p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-3 py-4 space-y-1">
            {navigation.map((item) => {
              const Icon = item.icon;
              const isActive = currentPage === item.id;
              
              return (
                <button
                  key={item.id}
                  onClick={() => onNavigate(item.id)}
                  className={cn(
                    'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200',
                    isActive
                      ? 'bg-primary-600 text-white'
                      : 'text-dark-400 hover:text-dark-50 hover:bg-dark-800'
                  )}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{item.name}</span>
                </button>
              );
            })}
          </nav>

          {/* Settings */}
          <div className="p-3 border-t border-dark-800">
            <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-dark-400 hover:text-dark-50 hover:bg-dark-800 transition-all duration-200">
              <Settings className="w-5 h-5" />
              <span className="font-medium">Settings</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile sidebar */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSidebarOpen(false)}
              className="fixed inset-0 bg-black/50 z-40 lg:hidden"
            />
            <motion.div
              initial={{ x: -256 }}
              animate={{ x: 0 }}
              exit={{ x: -256 }}
              transition={{ type: 'spring', damping: 30, stiffness: 300 }}
              className="fixed inset-y-0 left-0 w-64 bg-dark-900 border-r border-dark-800 z-50 lg:hidden"
            >
              <div className="flex flex-col h-full">
                {/* Logo */}
                <div className="flex items-center justify-between h-16 px-6 border-b border-dark-800">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-primary-600 rounded-lg">
                      <Shield className="w-6 h-6 text-white" />
                    </div>
                    <div>
                      <h1 className="text-xl font-bold text-dark-50">Aegis Zero</h1>
                      <p className="text-xs text-dark-400">Zero-Day Detection</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSidebarOpen(false)}
                    className="text-dark-400 hover:text-dark-50"
                  >
                    <X className="w-6 h-6" />
                  </button>
                </div>

                {/* Navigation */}
                <nav className="flex-1 px-3 py-4 space-y-1">
                  {navigation.map((item) => {
                    const Icon = item.icon;
                    const isActive = currentPage === item.id;
                    
                    return (
                      <button
                        key={item.id}
                        onClick={() => {
                          onNavigate(item.id);
                          setSidebarOpen(false);
                        }}
                        className={cn(
                          'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200',
                          isActive
                            ? 'bg-primary-600 text-white'
                            : 'text-dark-400 hover:text-dark-50 hover:bg-dark-800'
                        )}
                      >
                        <Icon className="w-5 h-5" />
                        <span className="font-medium">{item.name}</span>
                      </button>
                    );
                  })}
                </nav>

                {/* Settings */}
                <div className="p-3 border-t border-dark-800">
                  <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-dark-400 hover:text-dark-50 hover:bg-dark-800 transition-all duration-200">
                    <Settings className="w-5 h-5" />
                    <span className="font-medium">Settings</span>
                  </button>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <div className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b border-dark-800 bg-dark-900/80 backdrop-blur-sm px-4 lg:px-8">
          <button
            onClick={() => setSidebarOpen(true)}
            className="text-dark-400 hover:text-dark-50 lg:hidden"
          >
            <Menu className="w-6 h-6" />
          </button>

          <div className="flex-1" />

          {/* Status indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/20">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-sm font-medium text-green-500">System Active</span>
          </div>
        </div>

        {/* Page content */}
        <main className="p-4 lg:p-8">
          <motion.div
            key={currentPage}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
          >
            {children}
          </motion.div>
        </main>
      </div>
    </div>
  );
}
