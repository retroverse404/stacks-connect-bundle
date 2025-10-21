import path from 'path';
import { fileURLToPath } from 'url';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import replace from '@rollup/plugin-replace';
import nodePolyfills from 'rollup-plugin-node-polyfills';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = __dirname;

export default {
  input: path.join(repoRoot, 'node_modules', '@stacks', 'connect', 'dist', 'index.mjs'),
  output: {
    file: path.join(repoRoot, 'client', 'modules', 'vendor', 'stacks-connect.bundle.js'),
    format: 'esm',
    sourcemap: true,
    inlineDynamicImports: true,
  },
  plugins: [
    replace({
      preventAssignment: true,
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'development'),
    }),
    resolve({ browser: true, preferBuiltins: false }),
    commonjs({ requireReturnsDefault: 'preferred' }),
    nodePolyfills(),
  ],
  onwarn(warning, defaultHandler) {
    if (warning.code === 'CIRCULAR_DEPENDENCY') return;
    defaultHandler(warning);
  },
};
