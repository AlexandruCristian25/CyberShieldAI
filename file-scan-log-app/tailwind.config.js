/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class', // pentru suport dark/light mode
  theme: {
    extend: {
      colors: {
        primary: {
          light: '#ec4899',
          DEFAULT: '#d946ef',
          dark: '#a21caf',
        },
        danger: '#ef4444',
        success: '#22c55e',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
      },
      animation: {
        fadeIn: 'fadeIn 0.6s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  safelist: [
    'text-green-300',
    'text-red-300',
    'aria-busy',
    'disabled',
  ],
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
};
