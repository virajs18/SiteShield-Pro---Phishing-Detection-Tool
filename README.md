# SiteShield Pro 🛡️

**Advanced Phishing Detection & URL Security Scanner**

A modern, production-ready web application that provides real-time URL security analysis using the VirusTotal API. Built with React, TypeScript, and Tailwind CSS.

![SiteShield Pro Screenshot](https://siteshieldpro.netlify.app)

## 🌟 Features

- **Real-time URL Security Scanning** - Instantly analyze any website for threats
- **Advanced Threat Detection** - Identifies phishing, malware, and suspicious content
- **URL Normalization** - Automatically standardizes URLs for consistent analysis
- **Beautiful Modern UI** - Responsive design with smooth animations and gradients
- **Production Ready** - Optimized build with proper error handling
- **Mobile Responsive** - Works seamlessly across all device sizes

## 🚀 Live Demo

Visit the live application: [https://siteshieldpro.netlify.app](https://siteshieldpro.netlify.app)

## 🛠️ Tech Stack

- **Frontend**: React 18 + TypeScript
- **Styling**: Tailwind CSS
- **Icons**: Lucide React
- **Build Tool**: Vite
- **API**: VirusTotal API v3
- **Deployment**: Netlify

## 📋 Prerequisites

- Node.js 16+ 
- npm or yarn
- VirusTotal API key (free tier available)

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd siteshield-pro
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure API Key**
   - Get your free API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Update the `API_KEY` constant in `src/App.tsx`

4. **Start development server**
   ```bash
   npm run dev
   ```

5. **Open your browser**
   - Navigate to `http://localhost:5173`

## 🏗️ Build for Production

```bash
npm run build
npm run preview
```

## 🔒 Security Features

### Threat Detection Capabilities
- **Phishing Detection** - Identifies fake login pages and credential theft attempts
- **Malware Scanning** - Detects malicious downloads and infected sites
- **Suspicious Content** - Flags potentially harmful or deceptive websites
- **Real-time Analysis** - Uses multiple security engines for comprehensive scanning

### URL Processing
- **Smart Normalization** - Handles various URL formats consistently
- **Protocol Detection** - Automatically adds HTTPS when missing
- **Parameter Sorting** - Ensures consistent URL analysis
- **Validation** - Prevents invalid or malformed URL submissions

## 🎨 Design Features

- **Modern Gradient UI** - Beautiful blue-to-purple color scheme
- **Glassmorphism Effects** - Backdrop blur and transparency effects
- **Smooth Animations** - Hover states and micro-interactions
- **Responsive Layout** - Mobile-first design approach
- **Loading States** - Clear feedback during scanning process

## 📁 Project Structure

```
src/
├── App.tsx          # Main application component
├── main.tsx         # Application entry point
├── index.css        # Global styles and Tailwind imports
└── vite-env.d.ts    # TypeScript environment definitions

public/
└── vite.svg         # Application favicon

config/
├── vite.config.ts   # Vite configuration with API proxy
├── tailwind.config.js # Tailwind CSS configuration
├── tsconfig.json    # TypeScript configuration
└── postcss.config.js # PostCSS configuration
```

## 🔧 Configuration

### Vite Proxy Setup
The application uses a proxy to handle CORS issues with the VirusTotal API:

```typescript
server: {
  proxy: {
    '/vtapi': {
      target: 'https://www.virustotal.com/api/v3',
      changeOrigin: true,
      rewrite: (path) => path.replace(/^\/vtapi/, ''),
    }
  }
}
```

### API Integration
The app integrates with VirusTotal API v3 for URL analysis:
- Submits URLs for scanning
- Retrieves analysis results
- Processes threat statistics
- Provides user-friendly feedback

## 🚀 Deployment

### Netlify (Recommended)
1. Build the project: `npm run build`
2. Deploy the `dist` folder to Netlify
3. Configure environment variables if needed

### Other Platforms
The built application in the `dist` folder can be deployed to:
- Vercel
- GitHub Pages
- AWS S3 + CloudFront
- Any static hosting service

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for educational and security research purposes. Always exercise caution when visiting unknown websites, and use this tool as one part of a comprehensive security strategy.

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com) for providing the threat detection API
- [Lucide](https://lucide.dev) for the beautiful icon set
- [Tailwind CSS](https://tailwindcss.com) for the utility-first CSS framework
- [Vite](https://vitejs.dev) for the fast build tool

## 📞 Support

If you encounter any issues or have questions:
1. Check the [Issues](../../issues) page
2. Create a new issue with detailed information
3. Include browser version and error messages

---

**Built with ❤️ for web security and education**
