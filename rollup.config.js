import fs from 'fs'
import dts from 'rollup-plugin-dts'
import typescript from '@rollup/plugin-typescript'

import pkg from './package.json'
import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import {nodeResolve} from '@rollup/plugin-node-resolve'

const name = pkg.name
const license = fs.readFileSync('LICENSE').toString('utf-8').trim()
const banner = `
/**
 * ${name} v${pkg.version}
 * ${pkg.homepage}
 *
 * @license
 * ${license.replace(/\n/g, '\n * ')}
 */
`.trim()

const external = Object.keys(pkg.dependencies).filter((dependency) => dependency !== 'elliptic')
export default [
    {
        input: 'src/index.ts',
        output: {
            banner,
            file: pkg.main,
            format: 'cjs',
            sourcemap: true,
        },
        plugins: [nodeResolve(), json(), commonjs(), typescript({target: 'es6'})],
        external,
    },
    {
        input: 'src/index.ts',
        output: {
            banner,
            file: pkg.module,
            format: 'esm',
            sourcemap: true,
        },
        plugins: [nodeResolve(), json(), commonjs(), typescript({target: 'es2020'})],
        external,
    },
    {
        input: 'src/index.ts',
        output: {banner, file: pkg.types, format: 'esm'},

        plugins: [dts()],
    },
]
