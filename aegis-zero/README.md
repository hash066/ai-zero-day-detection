# Aegis Zero Dashboard# React + TypeScript + Vite



A professional, minimalistic React + Vite dashboard for the AI-Based Zero-Day Attack Detection System.This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.



## FeaturesCurrently, two official plugins are available:



- **Real-time Monitoring**: Live threat detection and system metrics- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) (or [oxc](https://oxc.rs) when used in [rolldown-vite](https://vite.dev/guide/rolldown)) for Fast Refresh

- **Threat Management**: View and manage security alerts- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

- **Device Monitoring**: Track all network devices and their security status

- **Network Analysis**: Monitor network traffic and flows## React Compiler

- **AI Model Management**: Track ML model performance and retrain models

- **Responsive Design**: Works seamlessly on desktop and mobile devicesThe React Compiler is enabled on this template. See [this documentation](https://react.dev/learn/react-compiler) for more information.



## Tech StackNote: This will impact Vite dev & build performances.



- **React 19** - UI framework## Expanding the ESLint configuration

- **TypeScript** - Type safety

- **Vite** - Build tool and dev serverIf you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

- **Tailwind CSS** - Styling

- **Framer Motion** - Animations```js

- **Recharts** - Data visualizationexport default defineConfig([

- **Lucide React** - Icon library  globalIgnores(['dist']),

- **date-fns** - Date formatting  {

    files: ['**/*.{ts,tsx}'],

## Getting Started    extends: [

      // Other configs...

### Prerequisites

      // Remove tseslint.configs.recommended and replace with this

- Node.js 18+ and npm      tseslint.configs.recommendedTypeChecked,

      // Alternatively, use this for stricter rules

### Installation      tseslint.configs.strictTypeChecked,

      // Optionally, add this for stylistic rules

1. Install dependencies:      tseslint.configs.stylisticTypeChecked,

   ```bash

   npm install      // Other configs...

   ```    ],

    languageOptions: {

2. Copy environment variables:      parserOptions: {

   ```bash        project: ['./tsconfig.node.json', './tsconfig.app.json'],

   cp .env.example .env        tsconfigRootDir: import.meta.dirname,

   ```      },

      // other options...

3. Configure your API endpoint in `.env`:    },

   ```env  },

   VITE_API_URL=http://localhost:8000/api])

   ``````



### DevelopmentYou can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:



Start the development server:```js

// eslint.config.js

```bashimport reactX from 'eslint-plugin-react-x'

npm run devimport reactDom from 'eslint-plugin-react-dom'

```

export default defineConfig([

The dashboard will be available at `http://localhost:5173`  globalIgnores(['dist']),

  {

### Build for Production    files: ['**/*.{ts,tsx}'],

    extends: [

```bash      // Other configs...

npm run build      // Enable lint rules for React

```      reactX.configs['recommended-typescript'],

      // Enable lint rules for React DOM

The build output will be in the `dist/` directory.      reactDom.configs.recommended,

    ],

### Preview Production Build    languageOptions: {

      parserOptions: {

```bash        project: ['./tsconfig.node.json', './tsconfig.app.json'],

npm run preview        tsconfigRootDir: import.meta.dirname,

```      },

      // other options...

## Project Structure    },

  },

```])

src/```

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
