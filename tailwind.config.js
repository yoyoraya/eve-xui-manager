/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/subscription.html',
    './static/subscription.js',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'Vazirmatn', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        bg: '#0B1121',
        card: '#151E32',
        primary: '#6366f1',
        accent: '#8b5cf6',
        success: '#10b981',
        text: '#e2e8f0',
        muted: '#64748b',
        border: '#1e293b',
      },
    },
  },
  plugins: [],
};
