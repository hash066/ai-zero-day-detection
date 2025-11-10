# Aegis Zero Dashboard

A professional, minimalistic React + Vite dashboard for the AI-Based Zero-Day Attack Detection System.

## Features

- **Real-time Monitoring**: Live threat detection and system metrics
- **Threat Management**: View and manage security alerts
- **Device Monitoring**: Track all network devices and their security status
- **Network Analysis**: Monitor network traffic and flows## React Compiler
- **AI Model Management**: Track ML model performance and retrain models
- **Responsive Design**: Works seamlessly on desktop and mobile devices

## Tech Stack

- **React 19** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Styling
- **Framer Motion** - Animations
- **Recharts** - Data
- **Lucide React** - Icon library
- **date-fns** - Date formatting

## Getting Started

### Prerequisites

- Node.js 18+ and npm

### Installation

1. Install dependencies:

   ```bash
   npm install
   ```

2. Copy environment variables:

   ```bash
   cp .env.example .env
   ```

3. Configure your API endpoint in `.env`

   ```env
   VITE_API_URL=http://localhost:8000/api
   ``````

### Development

Start the development server:

```bash
npm run dev
```

The dashboard will be available at `http://localhost:5173`

### Build for Production

```bash
npm run build

```

The build output will be in the `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

## Project Structure

```
src/
├── components/          # Reusable UI components
│   ├── Layout.tsx      # Main layout with sidebar
│   ├── StatCard.tsx    # Statistics card component
│   ├── AlertCard.tsx   # Threat alert card
│   ├── DeviceCard.tsx  # Device status card
│   └── Chart.tsx       # Chart wrapper component
├── pages/              # Page components
│   ├── Dashboard.tsx   # Main dashboard
│   ├── Alerts.tsx      # Threat alerts page
│   ├── Devices.tsx     # Device monitoring page
│   ├── NetworkMonitor.tsx  # Network traffic page
│   └── AIModels.tsx    # ML models page
├── services/           # API and data services
│   ├── api.ts          # API service layer
│   └── mockData.ts     # Mock data for development
├── types/              # TypeScript type definitions
│   └── index.ts        # Shared types
├── lib/                # Utility functions
│   └── utils.ts        # Helper functions
├── App.tsx             # Main app component
└── main.tsx            # App entry point
```

## Integrating with Backend

The dashboard uses mock data by default. To connect to your backend:

1. Update the `VITE_API_URL` in your `.env` file

2. The API service (`src/services/api.ts`) is already set up with the following endpoints:

   - `GET /api/dashboard/stats` - Dashboard statistics
   - `GET /api/alerts` - Threat alerts list
   - `GET /api/alerts/:id` - Single alert details
   - `PATCH /api/alerts/:id` - Update alert status
   - `GET /api/metrics/system` - System metrics
   - `GET /api/devices` - Devices list
   - `POST /api/devices/:id/isolate` - Isolate device
   - `GET /api/network/flows` - Network flows
   - `GET /api/models/metrics` - Model performance metrics
   - `POST /api/models/train` - Trigger model retraining

3. Replace the mock data imports in page components with actual API calls:

   ```typescript
   // Instead of:
   import { mockAlerts } from '../services/mockData';
   
   // Use:
   import { apiService } from '../services/api';
   
   // Then in your component:
   useEffect(() => {
     apiService.getAlerts().then(setAlerts);
   }, []);
   ```

## API Response Format

Expected API response formats are defined in `src/types/index.ts`. Key interfaces:

- `ThreatAlert` - Threat alert data
- `Device` - Network device information
- `NetworkFlow` - Network traffic flow
- `SystemMetrics` - Real-time system metrics
- `ModelMetrics` - ML model performance
- `DashboardStats` - Dashboard overview data

## Customization

### Colors

Edit the color palette in `tailwind.config.js`:

```javascript
colors: {
  primary: { /* your primary color shades */ },
  dark: { /* your dark theme shades */ },
}
```

### Font

The dashboard uses **Plus Jakarta Sans**. To change it:

1. Update the font import in `src/index.css`
2. Update the `fontFamily` in `tailwind.config.js`

### Theme

The dashboard uses a dark theme by default. Colors and styles are managed through Tailwind CSS utility classes.

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## License

This project is part of the AI-Based Zero-Day Attack Detection System.
