import path from 'path';
import replace from '@rollup/plugin-replace';
import typescript from '@rollup/plugin-typescript';
import autoExternal from 'rollup-plugin-auto-external';
import dts from 'rollup-plugin-dts';
import type { RollupOptions } from 'rollup';

const base: RollupOptions = {
  input: 'src/index.ts',
  treeshake: {
    annotations: true,
    moduleSideEffects: false,
    propertyReadSideEffects: false,
    unknownGlobalSideEffects: false,
  },
};

const runtime: RollupOptions = {
  ...base,
  output: [
    {
      file: 'dist/index.mjs',
      format: 'esm',
      sourcemap: false,
    },
    {
      file: 'dist/index.cjs',
      format: 'cjs',
      exports: 'named',
      sourcemap: false,
    },
  ],
  plugins: [
    autoExternal(),
    typescript({
      tsconfig: 'tsconfig.build.json',
    }),
    replace({
      values: {
        'import.meta.vitest': 'undefined',
      },
      preventAssignment: true,
    }),
  ],
};

const typesBuild: RollupOptions = {
  input: 'src/index.ts',
  output: {
    file: path.resolve('dist', 'index.d.ts'),
    format: 'esm',
  },
  plugins: [
    dts({
      tsconfig: 'tsconfig.build.json',
      respectExternal: true,
    }),
  ],
};

export default [runtime, typesBuild];
