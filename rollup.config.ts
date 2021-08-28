import { defineConfig } from 'rollup'
import commonjs from 'rollup-plugin-commonjs'
import del from 'rollup-plugin-delete'
import dts from 'rollup-plugin-dts'
import json from 'rollup-plugin-json'
import resolve from 'rollup-plugin-node-resolve'
import sourceMaps from 'rollup-plugin-sourcemaps'
import { terser } from 'rollup-plugin-terser'
import typescript from 'rollup-plugin-typescript2'

export default defineConfig([
  {
    input: 'src/index.ts',
    output: [
      {
        file: 'dist/react-auth.min.js',
        name: 'reactAuth',
        format: 'umd',
        sourcemap: true,
        globals: {
          react: 'React',
          'react-dom': 'ReactDOM',
          crypto: 'crypto',
        },
      },
    ],
    external: ['react', 'crypto'],
    watch: {
      include: 'src/**',
    },
    plugins: [
      del({ targets: 'dist/*', runOnce: true }),
      // Allow json resolution
      json(),
      // Compile TypeScript files
      typescript({ useTsconfigDeclarationDir: true }),
      // Allow bundling cjs modules (unlike webpack, rollup doesn't understand cjs)
      commonjs(),
      // Allow node_modules resolution, so you can use 'external' to control
      // which external modules to include in the bundle
      // https://github.com/rollup/rollup-plugin-node-resolve#usage
      resolve(),

      // Resolve source maps to the original source
      sourceMaps(),
      // Minify output
      terser(),
    ],
  },
  {
    input: './dist/index.d.ts',
    output: [{ file: 'dist/react-auth.d.ts', format: 'es' }],
    plugins: [
      dts(),
      del({
        targets: 'dist/*',
        ignore: [
          'dist/react-auth.d.ts',
          'dist/react-auth.min.js',
          'dist/react-auth.min.js.map',
        ],
        runOnce: true,
        hook: 'buildEnd',
      }),
    ],
  },
])
