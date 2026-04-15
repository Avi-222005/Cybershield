/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: 'var(--cs-bg)',
          surface: 'var(--cs-surface)',
          card: 'var(--cs-card)',
          border: 'var(--cs-border)',
          blue: '#0d6efd',
          'blue-dark': '#0b5ed7',
          'blue-light': '#6ea8fe',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        glow: 'glow 2s ease-in-out infinite alternate',
        'spin-slow': 'spin 8s linear infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px #0d6efd, 0 0 10px #0d6efd' },
          '100%': { boxShadow: '0 0 10px #0d6efd, 0 0 25px #0d6efd, 0 0 40px #0d6efd20' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      },
    },
  },
  plugins: [],
}
