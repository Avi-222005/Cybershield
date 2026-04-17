import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import {
  Shield,
  Globe,
  Wifi,
  Lock,
  FileSearch,
  ChevronRight,
  LayersIcon,
  Cpu,
  Database,
  Radar,
} from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'

const features = [
  {
    icon: Radar,
    title: 'Unified Recon Scanner',
    description:
      'Run one-click multi-module reconnaissance with unified scoring, prioritized findings, and executive-grade remediation output.',
    href: '/unified-recon',
    accentColor: '#06b6d4',
    tags: ['One-Click Recon', 'Unified Score', 'Exportable Reports'],
  },
  {
    icon: Globe,
    title: 'URL Phishing Checker',
    description:
      'Hybrid AI analysis combining 12 custom structural indicators with VirusTotal\'s 70+ security engine intelligence for maximum accuracy.',
    href: '/phishing-checker',
    accentColor: '#0d6efd',
    tags: ['12 Indicators', 'VirusTotal', 'Hybrid AI'],
  },
  {
    icon: Wifi,
    title: 'IP Reputation Checker',
    description:
      'Geolocation tracking, VPN/proxy detection, ISP analysis, and multi-vendor threat intelligence for any IPv4 or IPv6 address.',
    href: '/ip-checker',
    accentColor: '#3b82f6',
    tags: ['Geolocation', 'VPN Detection', 'IPv4 + IPv6'],
  },
  {
    icon: Lock,
    title: 'SSL Certificate Checker',
    description:
      'Validate TLS certificates, verify certificate authority trust chains, and track expiry dates to prevent security lapses.',
    href: '/ssl-checker',
    accentColor: '#10b981',
    tags: ['TLS/SSL', 'Expiry Tracking', 'CA Verification'],
  },
  {
    icon: FileSearch,
    title: 'WHOIS Lookup',
    description:
      'Full domain registration intelligence: ownership history, registrar details, registrant contacts, and name server data.',
    href: '/whois-lookup',
    accentColor: '#0d6efd',
    tags: ['Domain Intel', 'Registrar', 'Ownership Info'],
  },
]

const stats = [
  { label: 'Security Engines', value: '70+', icon: Shield },
  { label: 'Phishing Indicators', value: '12', icon: Cpu },
  { label: 'Threat Categories', value: '8+', icon: LayersIcon },
  { label: 'Data Sources', value: '3', icon: Database },
]

const cardVariants = {
  hidden: { opacity: 0, y: 28 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.45, delay: i * 0.1, ease: 'easeOut' },
  }),
}

export default function Home() {
  return (
    <PageWrapper>
      {/* ── Hero ─────────────────────────────── */}
      <section className="pt-32 pb-20 px-6">
        <div className="max-w-5xl mx-auto text-center">
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-[#0d6efd]/30 bg-[#0d6efd]/8 text-[#0d6efd] text-xs font-mono mb-8"
          >
            <Shield size={12} />
            Advanced Cyber Threat Intelligence Platform
          </motion.div>

          {/* Title */}
          <motion.h1
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="text-5xl sm:text-6xl md:text-7xl font-extrabold mb-6 leading-[1.1] tracking-tight"
          >
            <span className="text-white">Cyber</span>
            <span className="gradient-text-cyan">Shield</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="text-lg sm:text-xl text-gray-400 max-w-2xl mx-auto mb-10 leading-relaxed"
          >
            Real-time threat detection powered by hybrid AI analysis and 70+ security
            intelligence engines. Protect against phishing, malicious IPs, and certificate fraud.
          </motion.p>

          {/* CTAs */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="flex flex-wrap justify-center gap-3 mb-16"
          >
            <Link
              to="/phishing-checker"
              className="group flex items-center gap-2 px-7 py-3.5 bg-[#0d6efd] hover:bg-[#0b5ed7] !text-white font-semibold rounded-xl transition-all duration-200 text-sm shadow-lg shadow-[#0d6efd]/25"
            >
              Analyze a URL
              <ChevronRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
            </Link>
            <Link
              to="/ip-checker"
              className="flex items-center gap-2 px-7 py-3.5 border border-white/15 hover:border-[#0d6efd]/40 text-gray-300 hover:text-white rounded-xl transition-all duration-200 text-sm"
            >
              Check IP Reputation
            </Link>
          </motion.div>

          {/* Stats */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-xl mx-auto"
          >
            {stats.map(({ label, value, icon: Icon }) => (
              <div key={label} className="glass-card rounded-xl p-4 text-center">
                <Icon size={16} className="text-[#0d6efd]/70 mx-auto mb-2" />
                <div className="text-2xl font-bold font-mono text-[#0d6efd]">{value}</div>
                <div className="text-xs text-gray-500 mt-0.5">{label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Feature cards ────────────────────── */}
      <section className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="text-center mb-12"
          >
            <h2 className="text-3xl font-bold text-white mb-3">Security Intelligence Suite</h2>
            <p className="text-gray-500 max-w-md mx-auto text-sm">
              Specialized modules delivering comprehensive threat visibility
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 gap-5">
            {features.map((feat, i) => (
              <motion.div
                key={feat.title}
                custom={i}
                variants={cardVariants}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true }}
                whileHover={{ y: -3 }}
              >
                <Link
                  to={feat.href}
                  className="group block glass-card-hover rounded-2xl p-6 h-full transition-all duration-200"
                >
                  <div className="flex items-start gap-4 mb-3">
                    <div
                      className="p-2.5 rounded-xl shrink-0"
                      style={{ background: `${feat.accentColor}15`, border: `1px solid ${feat.accentColor}25` }}
                    >
                      <feat.icon size={20} style={{ color: feat.accentColor }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-white group-hover:text-[#6ea8fe] transition-colors text-[15px] mb-2">
                        {feat.title}
                      </h3>
                      <div className="flex flex-wrap gap-1.5">
                        {feat.tags.map((tag) => (
                          <span
                            key={tag}
                            className="text-[10px] px-2 py-0.5 rounded-full border border-white/8 text-gray-500 bg-white/3"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                    <ChevronRight
                      size={18}
                      className="shrink-0 text-gray-600 group-hover:text-[#0d6efd] group-hover:translate-x-0.5 transition-all mt-0.5"
                    />
                  </div>
                  <p className="text-gray-500 text-sm leading-relaxed">{feat.description}</p>
                </Link>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ─────────────────────── */}
      <section className="py-20 px-6 border-t border-white/5">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="mb-12"
          >
            <h2 className="text-3xl font-bold text-white mb-3">Hybrid Detection Engine</h2>
            <p className="text-gray-500 text-sm max-w-lg mx-auto">
              Dual-layer analysis combining algorithmic pattern matching with real-time threat intelligence
            </p>
          </motion.div>

          <div className="grid sm:grid-cols-3 gap-5">
            {[
              {
                step: '01',
                title: 'Custom Analysis',
                desc: '12 algorithmic URL indicators analyze structure, keywords, TLD risk, brand spoofing, punycode, and more.',
                color: '#0d6efd',
              },
              {
                step: '02',
                title: 'Threat Intelligence',
                desc: '70+ security engines via VirusTotal API cross-reference against continuously updated global threat databases.',
                color: '#3b82f6',
              },
              {
                step: '03',
                title: 'Hybrid Verdict',
                desc: 'Weighted fusion (65% custom + 35% API) produces a precise 0–100 risk score with SAFE / SUSPICIOUS / MALICIOUS verdict.',
                color: '#6ea8fe',
              },
            ].map((item, i) => (
              <motion.div
                key={item.step}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.45, delay: i * 0.12 }}
                className="glass-card rounded-xl p-6 text-left"
              >
                <div
                  className="text-4xl font-bold font-mono mb-4"
                  style={{ color: item.color, opacity: 0.85 }}
                >
                  {item.step}
                </div>
                <h3 className="text-white font-semibold mb-2 text-[15px]">{item.title}</h3>
                <p className="text-gray-500 text-sm leading-relaxed">{item.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
    </PageWrapper>
  )
}
