/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Base: deep desaturated slate (not pure black) — a calmer operator surface.
        base: {
          900: '#0b0f14', // app background
          800: '#111823', // panels
          700: '#1a2432', // raised / hover
          600: '#26323f', // borders
          500: '#3a4a5c', // muted lines
        },
        ink: {
          DEFAULT: '#e6edf3', // primary text
          dim: '#9fb0c0',     // secondary
          faint: '#5f7183',   // tertiary / captions
        },
        // Single reserved "signal" accent — amber, used only for active/live signals.
        signal: {
          DEFAULT: '#f5a524',
          soft: '#ffbe4d',   // brighter amber for hover/active affordance
          dim: '#7a5417',    // muted amber for subdued fills
        },
        // Severity scale (deliberate, colorblind-tuned steps).
        sev: {
          critical: '#ff4d6d',
          high: '#ff8c42',
          medium: '#f5c518',
          low: '#4cc9f0',
          info: '#7d8fa1',
        },
        good: '#3ddc97',
      },
      fontFamily: {
        // Display: condensed grotesque for headers; body: humanist sans; data: mono.
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        panel: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)',
      },
      keyframes: {
        'pulse-ring': {
          '0%': { boxShadow: '0 0 0 0 rgba(245,165,36,0.5)' },
          '70%': { boxShadow: '0 0 0 8px rgba(245,165,36,0)' },
          '100%': { boxShadow: '0 0 0 0 rgba(245,165,36,0)' },
        },
        ticker: { '0%': { transform: 'translateY(0)' }, '100%': { transform: 'translateY(-50%)' } },
      },
      animation: {
        'pulse-ring': 'pulse-ring 2s cubic-bezier(0.4,0,0.6,1) infinite',
      },
    },
  },
  plugins: [],
};
