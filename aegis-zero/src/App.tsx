import { useState } from 'react';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { Alerts } from './pages/Alerts';
import { Devices } from './pages/Devices';
import { NetworkMonitor } from './pages/NetworkMonitor';
import { AIModels } from './pages/AIModels';

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />;
      case 'alerts':
        return <Alerts />;
      case 'devices':
        return <Devices />;
      case 'network':
        return <NetworkMonitor />;
      case 'models':
        return <AIModels />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <Layout currentPage={currentPage} onNavigate={setCurrentPage}>
      {renderPage()}
    </Layout>
  );
}

export default App;
