/**
 * End-to-end checks for the PKCE flow, over real HTTP against WordPress Playground.
 *
 * Covers cookie login, the consent form, the redirect back to the client, the
 * token exchange, and using the token on the REST API. Redirects are never
 * followed, so every Location header is checked.
 */
import { createHash, randomBytes } from 'node:crypto';
import { test, expect, request, type APIRequestContext } from '@playwright/test';
import { runCLI, type RunCLIServer } from '@wp-playground/cli';

const CALLBACK = 'http://127.0.0.1:9876/callback';
const INVALID_CODE = 'oauth2.client.check_authorization_code.invalid_code';

let cli: RunCLIServer;
let browser: APIRequestContext;
let client: APIRequestContext;
let clients: { required: string; optional: string };

test.beforeAll( async () => {
	cli = await runCLI( {
		command: 'server',
		port: Number( process.env.E2E_PORT ?? 9400 ),
		quiet: true,
		mount: [ { hostPath: process.cwd(), vfsPath: '/wordpress/wp-content/plugins/oauth2' } ],
		blueprint: {
			steps: [ { step: 'activatePlugin', pluginPath: 'oauth2/plugin.php' } ],
		},
	} );

	const created = await cli.playground.run( {
		code: `<?php
			require '/wordpress/wp-load.php';
			$ids = [];
			foreach ( [ 'required' => true, 'optional' => false ] as $name => $pkce_required ) {
				$client = WP\\OAuth2\\Client::create( [
					'name'        => "PKCE $name",
					'description' => 'Created by the e2e tests.',
					'meta'        => [
						'callback'      => '${ CALLBACK }',
						'type'          => 'public',
						'pkce_required' => $pkce_required,
					],
				] );
				$client->approve();
				$ids[ $name ] = $client->get_id();
			}
			echo wp_json_encode( $ids );
		`,
	} );
	clients = JSON.parse( created.text );

	// "browser" holds the logged-in user's cookies; "client" is the OAuth app, with none.
	browser = await request.newContext( { baseURL: cli.serverUrl } );
	client = await request.newContext( { baseURL: cli.serverUrl } );

	await browser.get( '/wp-login.php' );
	const login = await browser.post( '/wp-login.php', {
		form: { log: 'admin', pwd: 'password', 'wp-submit': 'Log In', testcookie: '1' },
		maxRedirects: 0,
	} );
	expect( login.status() ).toBe( 302 );
} );

test.afterAll( async () => {
	await browser?.dispose();
	await client?.dispose();
	await cli?.server?.close();
} );

function pkcePair() {
	const verifier = randomBytes( 48 ).toString( 'base64url' ).slice( 0, 64 );
	const challenge = createHash( 'sha256' ).update( verifier ).digest( 'base64url' );
	return { verifier, challenge };
}

type Params = Record< string, string > | [ string, string ][];

/**
 * Run the authorize step as the logged-in user.
 *
 * Submits the consent form when the server shows it. Returns where the
 * server redirected to, and whether the form was shown.
 */
async function authorize(
	clientId: string,
	params: Params = {},
	{ responseType = 'code', submit = 'authorize' } = {}
) {
	const query = new URLSearchParams( [
		[ 'action', 'oauth2_authorize' ],
		[ 'response_type', responseType ],
		[ 'client_id', clientId ],
		[ 'redirect_uri', CALLBACK ],
		...( Array.isArray( params ) ? params : Object.entries( params ) ),
	] );

	const page = await browser.get( `/wp-login.php?${ query }`, { maxRedirects: 0 } );
	if ( page.status() === 302 ) {
		return { location: new URL( page.headers().location ), formShown: false };
	}

	const html = await page.text();
	expect( html ).toContain( 'oauth2_authorize_form' );
	const action = html.match( /id="oauth2_authorize_form" action="([^"]+)"/ )![ 1 ].replace( /&(amp|#0?38);/g, '&' );
	const nonce = html.match( /name="_wpnonce" value="([^"]+)"/ )![ 1 ];

	const submitted = await browser.post( action, {
		form: { _wpnonce: nonce, _wp_http_referer: action, 'wp-submit': submit },
		maxRedirects: 0,
	} );
	expect( submitted.status() ).toBe( 302 );
	return { location: new URL( submitted.headers().location ), formShown: true };
}

async function getCode( clientId: string, params: Params = {} ) {
	const { location } = await authorize( clientId, params );
	const code = location.searchParams.get( 'code' );
	expect( code, `no code in ${ location }` ).toBeTruthy();
	return code!;
}

async function exchange( params: Record< string, string >, { json = false, query = {} } = {} ) {
	const url = `/?${ new URLSearchParams( { rest_route: '/oauth2/access_token', ...query } ) }`;
	const response = await client.post( url, json ? { data: params } : { form: params } );
	return { status: response.status(), body: await response.json() };
}

async function s256Code() {
	const pair = pkcePair();
	const code = await getCode( clients.required, { code_challenge: pair.challenge, code_challenge_method: 'S256' } );
	return { ...pair, code };
}

test( 'RFC 8414 metadata lists the supported PKCE methods', async () => {
	const response = await client.get( '/.well-known/oauth-authorization-server' );
	expect( ( await response.json() ).code_challenge_methods_supported ).toContain( 'S256' );
} );

test.describe( 'S256 flow', () => {
	test( 'code and verifier exchange for a token that works on the REST API', async () => {
		const { verifier, challenge } = pkcePair();
		const { location, formShown } = await authorize( clients.required, {
			state: 'st-1',
			code_challenge: challenge,
			code_challenge_method: 'S256',
		} );

		expect( formShown ).toBe( true );
		expect( location.origin + location.pathname ).toBe( CALLBACK );
		expect( location.searchParams.get( 'state' ) ).toBe( 'st-1' );

		const code = location.searchParams.get( 'code' )!;
		const token = await exchange( { grant_type: 'authorization_code', client_id: clients.required, code, code_verifier: verifier } );
		expect( token.status ).toBe( 200 );
		expect( token.body.access_token ).toBeTruthy();

		const me = await client.get( '/?rest_route=/wp/v2/users/me', {
			headers: { Authorization: `Bearer ${ token.body.access_token }` },
		} );
		expect( me.status() ).toBe( 200 );
		expect( ( await me.json() ).slug ).toBe( 'admin' );

		const reuse = await exchange( { grant_type: 'authorization_code', client_id: clients.required, code, code_verifier: verifier } );
		expect( reuse.body.code ).toBe( INVALID_CODE );
	} );

	test( 'verifier in a JSON body is accepted', async () => {
		const { code, verifier } = await s256Code();
		const token = await exchange( { grant_type: 'authorization_code', client_id: clients.required, code, code_verifier: verifier }, { json: true } );
		expect( token.status ).toBe( 200 );
	} );
} );

test.describe( 'token exchange is refused', () => {
	test( 'wrong verifier, and the code is burned afterwards', async () => {
		const { code, verifier } = await s256Code();

		const wrong = await exchange( { grant_type: 'authorization_code', client_id: clients.required, code, code_verifier: pkcePair().verifier } );
		expect( wrong.status ).toBe( 400 );
		expect( wrong.body.data.error ).toBe( 'invalid_grant' );

		const retry = await exchange( { grant_type: 'authorization_code', client_id: clients.required, code, code_verifier: verifier } );
		expect( retry.body.code ).toBe( INVALID_CODE );
	} );

	test( 'missing verifier', async () => {
		const { code } = await s256Code();
		const token = await exchange( { grant_type: 'authorization_code', client_id: clients.required, code } );
		expect( token.status ).toBe( 400 );
		expect( token.body.code ).toContain( 'missing_verifier' );
	} );

	test( 'verifier sent only in the URL query string', async () => {
		const { code, verifier } = await s256Code();
		const token = await exchange( { grant_type: 'authorization_code', client_id: clients.required, code }, { query: { code_verifier: verifier } } );
		expect( token.status ).toBe( 400 );
		expect( token.body.code ).toContain( 'missing_verifier' );
	} );

	test( 'verifier sent for a code issued without PKCE', async () => {
		const code = await getCode( clients.optional );
		const token = await exchange( { grant_type: 'authorization_code', client_id: clients.optional, code, code_verifier: pkcePair().verifier } );
		expect( token.status ).toBe( 400 );
		expect( token.body.code ).toContain( 'unexpected_verifier' );
	} );

	test( 'code redeemed by a different client', async () => {
		const { code, verifier } = await s256Code();
		const token = await exchange( { grant_type: 'authorization_code', client_id: clients.optional, code, code_verifier: verifier } );
		expect( token.body.code ).toBe( INVALID_CODE );
	} );
} );

test.describe( 'authorize step is refused before consent', () => {
	const cases: [ string, () => Promise< { location: URL; formShown: boolean } > ][] = [
		[ 'required client without a challenge', () => authorize( clients.required, { state: 'st-6' } ) ],
		[ 'required client using plain', () => authorize( clients.required, { code_challenge: pkcePair().verifier, code_challenge_method: 'plain' } ) ],
		[ 'array-valued code_challenge', () => authorize( clients.optional, [ [ 'code_challenge[]', 'x' ] ] ) ],
		[ 'method without a challenge', () => authorize( clients.optional, { code_challenge_method: 'S256' } ) ],
		[ 'unsupported method', () => authorize( clients.optional, { code_challenge: 'a'.repeat( 43 ), code_challenge_method: 'S512' } ) ],
		[ 'malformed S256 challenge', () => authorize( clients.optional, { code_challenge: 'short', code_challenge_method: 'S256' } ) ],
	];

	for ( const [ name, run ] of cases ) {
		test( `${ name }: invalid_request redirect to the client`, async () => {
			const { location, formShown } = await run();
			expect( formShown ).toBe( false );
			expect( location.origin + location.pathname ).toBe( CALLBACK );
			expect( location.searchParams.get( 'error' ) ).toBe( 'invalid_request' );
		} );
	}

	test( 'the error redirect keeps the state', async () => {
		const { location } = await authorize( clients.required, { state: 'st-6' } );
		expect( location.searchParams.get( 'state' ) ).toBe( 'st-6' );
	} );

	test( 'plain on a required client names S256 in the error', async () => {
		const { location } = await authorize( clients.required, { code_challenge: pkcePair().verifier, code_challenge_method: 'plain' } );
		expect( location.searchParams.get( 'error_description' ) ).toContain( 'S256' );
	} );
} );

test.describe( 'clients with optional PKCE', () => {
	test( 'plain exchanges for a token', async () => {
		const { verifier } = pkcePair();
		const code = await getCode( clients.optional, { code_challenge: verifier, code_challenge_method: 'plain' } );
		const token = await exchange( { grant_type: 'authorization_code', client_id: clients.optional, code, code_verifier: verifier } );
		expect( token.status ).toBe( 200 );
	} );

	test( 'no PKCE still exchanges for a token', async () => {
		const code = await getCode( clients.optional );
		const token = await exchange( { grant_type: 'authorization_code', client_id: clients.optional, code } );
		expect( token.status ).toBe( 200 );
	} );
} );

test( 'implicit grant is refused for a PKCE-required client, in the fragment', async () => {
	const { location, formShown } = await authorize( clients.required, { state: 'st-13' }, { responseType: 'token' } );
	const fragment = new URLSearchParams( location.hash.slice( 1 ) );

	expect( formShown ).toBe( false );
	expect( location.origin + location.pathname ).toBe( CALLBACK );
	expect( fragment.get( 'error' ) ).toBe( 'unauthorized_client' );
	expect( fragment.get( 'state' ) ).toBe( 'st-13' );
} );

test( 'cancel on the consent form sends access_denied', async () => {
	const { challenge } = pkcePair();
	const { location, formShown } = await authorize(
		clients.required,
		{ code_challenge: challenge, code_challenge_method: 'S256' },
		{ submit: 'cancel' }
	);

	expect( formShown ).toBe( true );
	expect( location.searchParams.get( 'error' ) ).toBe( 'access_denied' );
} );
