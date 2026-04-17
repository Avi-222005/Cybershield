import { Suspense, lazy } from 'react'
import { Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { ThemeProvider } from './context/ThemeContext'
import { ToastProvider } from './context/ToastContext'
import Navbar from './components/layout/Navbar'
import Footer from './components/layout/Footer'
import DotMatrixBackground from './components/background/DotMatrixBackground'
import LoadingSpinner from './components/ui/LoadingSpinner'
import Home from './pages/Home'
import PhishingChecker from './pages/PhishingChecker'
import IPChecker from './pages/IPChecker'
import SSLChecker from './pages/SSLChecker'
import WhoisLookup from './pages/WhoisLookup'
import DNSLookup from './pages/DNSLookup'
import SubdomainFinder from './pages/SubdomainFinder'
import PortScanner from './pages/PortScanner'
import HTTPHeaderAnalyzer from './pages/HTTPHeaderAnalyzer'
import TechStackAnalyzer from './pages/TechStackAnalyzer'
import EmailHeaderAnalyzer from './pages/EmailHeaderAnalyzer'
import UnifiedReconScanner from './pages/UnifiedReconScanner'

const HashGeneratorTool = lazy(() => import('./pages/tools/HashGeneratorTool'))
const PasswordGeneratorTool = lazy(() => import('./pages/tools/PasswordGeneratorTool'))
const Base64Tool = lazy(() => import('./pages/tools/Base64Tool'))
const JwtDecoderTool = lazy(() => import('./pages/tools/JwtDecoderTool'))
const HashIdentifierTool = lazy(() => import('./pages/tools/HashIdentifierTool'))
const QrGeneratorTool = lazy(() => import('./pages/tools/QrGeneratorTool'))

function LazyPage({ children }: { children: JSX.Element }) {
  return (
    <Suspense
      fallback={(
        <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-28 pb-20">
          <div className="glass-card rounded-2xl">
            <LoadingSpinner label="Loading tool..." />
          </div>
        </div>
      )}
    >
      {children}
    </Suspense>
  )
}

function App() {
  const location = useLocation()

  return (
    <ThemeProvider>
      <ToastProvider>
        <div className="min-h-screen bg-cyber-bg relative overflow-x-hidden transition-colors duration-300">
          <DotMatrixBackground />
          <div className="relative z-10 flex flex-col min-h-screen">
            <Navbar />
            <main className="flex-1">
              <AnimatePresence mode="wait">
                <Routes location={location} key={location.pathname}>
                  <Route path="/" element={<Home />} />
                  <Route path="/phishing-checker" element={<PhishingChecker />} />
                  <Route path="/ip-checker" element={<IPChecker />} />
                  <Route path="/ssl-checker" element={<SSLChecker />} />
                  <Route path="/whois-lookup" element={<WhoisLookup />} />
                  <Route path="/dns-lookup" element={<DNSLookup />} />
                  <Route path="/subdomain-finder" element={<SubdomainFinder />} />
                  <Route path="/port-scanner" element={<PortScanner />} />
                  <Route path="/http-header-analyzer" element={<HTTPHeaderAnalyzer />} />
                  <Route path="/email-header-analyzer" element={<EmailHeaderAnalyzer />} />
                  <Route path="/tech-stack-analyzer" element={<TechStackAnalyzer />} />
                  <Route path="/unified-recon" element={<UnifiedReconScanner />} />
                  <Route path="/tools/hash-generator" element={<LazyPage><HashGeneratorTool /></LazyPage>} />
                  <Route path="/tools/password-generator" element={<LazyPage><PasswordGeneratorTool /></LazyPage>} />
                  <Route path="/tools/base64" element={<LazyPage><Base64Tool /></LazyPage>} />
                  <Route path="/tools/jwt-decoder" element={<LazyPage><JwtDecoderTool /></LazyPage>} />
                  <Route path="/tools/hash-identifier" element={<LazyPage><HashIdentifierTool /></LazyPage>} />
                  <Route path="/tools/qr-generator" element={<LazyPage><QrGeneratorTool /></LazyPage>} />
                </Routes>
              </AnimatePresence>
            </main>
            <Footer />
          </div>
        </div>
      </ToastProvider>
    </ThemeProvider>
  )
}

export default App
