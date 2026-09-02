export default {
  plugins: {
    autoprefixer: {
      overrideBrowserslist: [
        'last 2 Chrome versions',
        'last 2 Firefox versions',
        'last 2 Edge versions',
        'last 2 Safari versions',
        'Firefox >= 78',
        'Chrome >= 80',
        'Edge >= 80',
        'Safari >= 14',
      ],
      flexbox: 'no-2009',
      grid: 'autoplace',
    },
  },
}
