import { useEffect, useMemo, useRef, useState, type ElementType } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  ChevronDown,
  Menu,
  X,
  Sun,
  Moon,
  Globe,
  Wifi,
  Lock,
  FileSearch,
  Network,
  SearchCheck,
  ScanLine,
  FileCode2,
  Brain,
  MailSearch,
} from 'lucide-react'
import { AnimatePresence, motion } from 'framer-motion'
import { cn } from '../../lib/utils'
import { useTheme } from '../../context/ThemeContext'

type NavItem = { to: string; label: string; icon: ElementType }

const threatItems: NavItem[] = [
  { to: '/phishing-checker', label: 'URL Phishing Checker', icon: Globe },
  { to: '/ip-checker', label: 'IP Reputation Checker', icon: Wifi },
  { to: '/ssl-checker', label: 'SSL Certificate Checker', icon: Lock },
  { to: '/whois-lookup', label: 'WHOIS Lookup', icon: FileSearch },
]

const reconItems: NavItem[] = [
  { to: '/tech-stack-analyzer', label: 'Tech Stack Analyzer', icon: Brain },
  { to: '/dns-lookup', label: 'DNS Lookup', icon: Network },
  { to: '/subdomain-finder', label: 'Subdomain Finder', icon: SearchCheck },
  { to: '/port-scanner', label: 'Port & Service Scanner', icon: ScanLine },
  { to: '/http-header-analyzer', label: 'HTTP Header Analyzer', icon: FileCode2 },
  { to: '/email-header-analyzer', label: 'Email Header Analyzer', icon: MailSearch },
]

function Dropdown({
  label,
  items,
  open,
  setOpen,
  pathname,
}: {
  label: string
  items: NavItem[]
  open: boolean
  setOpen: (v: boolean) => void
  pathname: string
}) {
  const isGroupActive = items.some((i) => i.to === pathname)
  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className={cn(
          'px-3 py-2 rounded-lg text-sm font-medium flex items-center gap-1.5 transition-colors',
          isGroupActive ? 'text-[#0d6efd] bg-[#0d6efd]/10' : 'text-gray-400 hover:text-white hover:bg-white/5',
        )}
      >
        {label}
        <ChevronDown size={14} className={cn('transition-transform', open && 'rotate-180')} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 6 }}
            transition={{ duration: 0.16 }}
            className="absolute left-0 top-full mt-2 w-72 glass-card rounded-xl border border-white/10 p-1 z-50"
          >
            {items.map(({ to, label: itemLabel, icon: Icon }) => {
              const active = pathname === to
              return (
                <Link
                  key={to}
                  to={to}
                  className={cn(
                    'flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors',
                    active ? 'text-[#0d6efd] bg-[#0d6efd]/10' : 'text-gray-300 hover:text-white hover:bg-white/5',
                  )}
                >
                  <Icon size={15} />
                  {itemLabel}
                </Link>
              )
            })}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [openDesktop, setOpenDesktop] = useState<'threat' | 'recon' | null>(null)
  const [openMobile, setOpenMobile] = useState<'threat' | 'recon' | null>(null)
  const location = useLocation()
  const { theme, toggleTheme } = useTheme()
  const ref = useRef<HTMLDivElement | null>(null)

  const pathname = location.pathname

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => {
    setMenuOpen(false)
    setOpenDesktop(null)
    setOpenMobile(null)
  }, [pathname])

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (!ref.current) return
      if (!ref.current.contains(e.target as Node)) {
        setOpenDesktop(null)
      }
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  const homeActive = useMemo(() => pathname === '/', [pathname])

  return (
    <header
      className={cn(
        'fixed top-0 left-0 right-0 z-50 transition-all duration-300',
        scrolled ? 'glass-card border-b border-cyber-border' : 'bg-transparent border-b border-transparent',
      )}
    >
      <nav ref={ref} className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2.5 group">
          <img src="/logo.png" alt="CyberShield" className="h-8 w-auto object-contain" />
        </Link>

        <div className="hidden md:flex items-center gap-1">
          <Link
            to="/"
            className={cn(
              'px-3 py-2 rounded-lg text-sm font-medium transition-colors',
              homeActive ? 'text-[#0d6efd] bg-[#0d6efd]/10' : 'text-gray-400 hover:text-white hover:bg-white/5',
            )}
          >
            Home
          </Link>
          <Dropdown
            label="Threat Analysis"
            items={threatItems}
            open={openDesktop === 'threat'}
            setOpen={(v) => setOpenDesktop(v ? 'threat' : null)}
            pathname={pathname}
          />
          <Dropdown
            label="Recon Tools"
            items={reconItems}
            open={openDesktop === 'recon'}
            setOpen={(v) => setOpenDesktop(v ? 'recon' : null)}
            pathname={pathname}
          />
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={toggleTheme}
            className="p-2 rounded-lg text-gray-400 hover:text-[#0d6efd] hover:bg-[#0d6efd]/8 transition-colors"
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
          <button
            className="md:hidden p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
            onClick={() => setMenuOpen((v) => !v)}
            aria-label="Toggle menu"
          >
            {menuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </nav>

      <AnimatePresence>
        {menuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className="md:hidden glass-card border-t border-cyber-border"
          >
            <div className="max-w-7xl mx-auto px-4 py-3 space-y-1">
              <Link
                to="/"
                className={cn(
                  'block px-3 py-2 rounded-lg text-sm font-medium',
                  homeActive ? 'text-[#0d6efd] bg-[#0d6efd]/10' : 'text-gray-300 hover:bg-white/5',
                )}
              >
                Home
              </Link>

              <button
                onClick={() => setOpenMobile((v) => (v === 'threat' ? null : 'threat'))}
                className="w-full px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:bg-white/5 flex items-center justify-between"
              >
                Threat Analysis
                <ChevronDown size={14} className={cn('transition-transform', openMobile === 'threat' && 'rotate-180')} />
              </button>
              <AnimatePresence>
                {openMobile === 'threat' && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden pl-2">
                    {threatItems.map(({ to, label, icon: Icon }) => (
                      <Link key={to} to={to} className={cn('flex items-center gap-2 px-3 py-2 rounded-lg text-sm', pathname === to ? 'text-[#0d6efd] bg-[#0d6efd]/10' : 'text-gray-400 hover:bg-white/5')}>
                        <Icon size={15} />
                        {label}
                      </Link>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>

              <button
                onClick={() => setOpenMobile((v) => (v === 'recon' ? null : 'recon'))}
                className="w-full px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:bg-white/5 flex items-center justify-between"
              >
                Recon Tools
                <ChevronDown size={14} className={cn('transition-transform', openMobile === 'recon' && 'rotate-180')} />
              </button>
              <AnimatePresence>
                {openMobile === 'recon' && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden pl-2">
                    {reconItems.map(({ to, label, icon: Icon }) => (
                      <Link key={to} to={to} className={cn('flex items-center gap-2 px-3 py-2 rounded-lg text-sm', pathname === to ? 'text-[#0d6efd] bg-[#0d6efd]/10' : 'text-gray-400 hover:bg-white/5')}>
                        <Icon size={15} />
                        {label}
                      </Link>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  )
}
