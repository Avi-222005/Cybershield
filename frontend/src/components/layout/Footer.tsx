import { Link } from 'react-router-dom'

export default function Footer() {
  return (
    <footer className="border-t border-cyber-border mt-auto">
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          {/* Brand */}
          <div className="flex items-center gap-2">
            <img src="/logo.png" alt="CyberShield" className="h-6 w-auto object-contain" />
            <span className="text-gray-600 text-sm ml-1">
              © {new Date().getFullYear()} Advanced Threat Intelligence
            </span>
          </div>

          {/* Links */}
          <div className="flex items-center gap-6">
            {[
              { to: '/phishing-checker', label: 'URL Checker' },
              { to: '/ip-checker', label: 'IP Checker' },
              { to: '/ssl-checker', label: 'SSL' },
              { to: '/whois-lookup', label: 'WHOIS' },
            ].map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                className="text-xs text-gray-500 hover:text-[#0d6efd] transition-colors"
              >
                {label}
              </Link>
            ))}
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-cyber-border/50 text-center">
          <p className="text-xs text-gray-600 font-mono">
            Powered by VirusTotal
          </p>
        </div>
      </div>
    </footer>
  )
}
