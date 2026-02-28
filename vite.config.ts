/// <reference types="vitest" />
// Configure Vitest (https://vitest.dev/config/)
import {defineConfig} from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
    build: {
        lib: {
            entry: {
                index: 'src/index.ts',
                server: 'src/server.ts',
                client: 'src/client.ts'
            },
            formats: ['es', 'cjs'],
            fileName: (format, entryName) => `${entryName}.${format}.js`
        },
        rollupOptions: {
            external: [/^node:/, "crypto", "@sourceregistry/node-jwt"],
            output: {
                exports: "named"
            }
        },
        sourcemap: true,
        target: 'node22'
    },
    plugins: [dts()]
});
