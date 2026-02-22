import type { Config } from 'tailwindcss'

const config: Config = {
  content: ['./app/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0a0a0a',
        accent: '#00ff88',
        'accent-dim': '#00cc6a',
      },
    },
  },
  plugins: [],
}
export default config
