const path = require('path');

module.exports = {
  mode: 'production',
  entry: {
    background: './src/background.js',
    popup: './src/popup.js'
  },
  output: {
    filename: '[name].bundle.js',
    path: path.resolve(__dirname, 'build/dist'),
    clean: true
  },
  resolve: {
    fallback: {
      "crypto": false,
      "stream": false,
      "buffer": false
    }
  }
};
