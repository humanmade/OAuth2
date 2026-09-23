import { defineConfig } from '@playwright/test';

export default defineConfig( {
	testDir: './tests/e2e',
	// The specs share one Playground server, so run them one at a time.
	fullyParallel: false,
	workers: 1,
	forbidOnly: !! process.env.CI,
	reporter: process.env.CI ? [ [ 'list' ], [ 'github' ] ] : 'list',
	timeout: 120_000,
} );
