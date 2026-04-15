export default function LoadingSpinner({ label = 'Analyzing...' }: { label?: string }) {
  return (
    <div className="flex flex-col items-center gap-4 py-12">
      {/* Animated rings */}
      <div className="relative w-16 h-16">
        <div className="absolute inset-0 rounded-full border-2 border-[#0d6efd]/20 animate-ping" />
        <div className="absolute inset-0 rounded-full border-2 border-t-[#0d6efd] border-r-transparent border-b-transparent border-l-transparent animate-spin" />
        <div
          className="absolute inset-2 rounded-full border-2 border-t-transparent border-r-[#6ea8fe] border-b-transparent border-l-transparent animate-spin"
          style={{ animationDirection: 'reverse', animationDuration: '0.8s' }}
        />
        <div className="absolute inset-4 rounded-full bg-[#0d6efd]/10 border border-[#0d6efd]/20" />
      </div>
      <p className="text-sm text-gray-400 font-mono tracking-wide animate-pulse">{label}</p>
    </div>
  )
}
