import * as esbuild from 'esbuild';

/** Plugin that replaces unused opnet ABI modules (motoswap, stable) with empty exports. */
const stripAbisPlugin = {
    name: 'strip-opnet-abis',
    setup(build) {
        build.onResolve({ filter: /\/abi\/shared\/(json|interfaces)\/(motoswap|stable|generic)\// }, (args) => {
            return { path: args.path, namespace: 'empty-abi' };
        });
        build.onLoad({ filter: /.*/, namespace: 'empty-abi' }, () => {
            return { contents: 'export {}', loader: 'js' };
        });
    },
};

await esbuild.build({
    entryPoints: ['src/main.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile: 'dist/main.js',
    target: 'node22',
    banner: { js: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);" },
    alias: {
        'undici': '../../_shared/src/undici-shim.ts',
        'bip39': '../../_shared/src/bip39-shim.ts',
    },
    plugins: [stripAbisPlugin],
});
