const path = require('path');
const WasmPackPlugin = require('@wasm-tool/wasm-pack-plugin');

module.exports = {
  mode: 'production',
  entry: {
    index: "./js/index.js"
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
  },
  plugins: [
    new WasmPackPlugin({
      crateDirectory: path.resolve(__dirname)
    }),
  ],
  experiments: {
    asyncWebAssembly: true,
  }
};
