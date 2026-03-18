import * as esbuild from 'esbuild';

await esbuild.build({
    entryPoints: ['src/main.ts'],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    outfile: 'dist/main.cjs',
    target: 'node22',
    external: [
        '@sidan-lab/sidan-csl-rs-nodejs',
        'libsodium-sumo',
        'libsodium-wrappers-sumo',
    ],
});
