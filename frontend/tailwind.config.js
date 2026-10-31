/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Inter"', '"Plus Jakarta Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['"Plus Jakarta Sans"', '"Inter"', 'sans-serif'],
      },
      colors: {
        hdx: {
          dark: '#0B0F19',
          card: '#111827',
          surface: '#1F2937',
          border: '#374151',
          primary: '#EF4444',
          accent: '#F43F5E',
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#DC2626',
          solana: '#9945FF'
        }
      }
    },
  },
  plugins: [],
}

