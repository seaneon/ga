// tailwind.config.js
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/admin/*.html", // This line is CRITICAL for finding classes in your templates
    // If you have any other files that contain Tailwind classes (e.g., JavaScript files
    // if you were building dynamic components), you'd list them here too.
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
