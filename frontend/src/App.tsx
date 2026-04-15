import { Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { ThemeProvider } from './context/ThemeContext'
import Navbar from './components/layout/Navbar'
import Footer from './components/layout/Footer'
import DotMatrixBackground from './components/background/DotMatrixBackground'
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

function App() {
  const location = useLocation()

  return (
    <ThemeProvider>
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
              </Routes>
            </AnimatePresence>
          </main>
          <Footer />
        </div>
      </div>
    </ThemeProvider>
  )
}

export default App
