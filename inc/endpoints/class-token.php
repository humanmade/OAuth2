<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Endpoints;

use WP_Error;
use WP_Http;
use WP\OAuth2;
use WP_REST_Request;

/**
 * Token endpoint handler.
 */
class Token {
	public function register_routes() {
		register_rest_route(
			'oauth2',
			'/access_token',
			[
				'methods'  => 'POST',
				'callback' => [ $this, 'exchange_token' ],
				'args'     => [
					'grant_type' => [
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => [ $this, 'validate_grant_type' ],
					],
					'client_id'  => [
						'required'          => false,
						'type'              => 'string',
						'validate_callback' => 'rest_validate_request_arg',
					],
					'code'       => [
						'required'          => false,
						'type'              => 'string',
						'validate_callback' => 'rest_validate_request_arg',
					],
					'client_secret' => [
						'required'          => false,
						'type'              => 'string',
						'validate_callback' => 'rest_validate_request_arg',
					],
				],
			]
		);
	}

	/**
	 * Validates the given grant type.
	 *
	 * @param string $type Grant type.
	 *
	 * @return bool Whether or not the grant type is valid.
	 */
	public function validate_grant_type( $type ) {
		return in_array( $type, [ 'authorization_code', 'client_credentials' ], true );
	}

	/**
	 * Validates the token given in the request, and issues a new token for the user.
	 *
	 * @param WP_REST_Request $request Request object.
	 *
	 * @return array|WP_Error Token data on success, or error on failure.
	 */
	public function exchange_token( WP_REST_Request $request ) {
		// Handle client_credentials grant type
		if ( $request['grant_type'] === 'client_credentials' ) {
			if ( ! OAuth2\Admin\Settings\is_client_credentials_enabled() ) {
				return new WP_Error(
					'oauth2.endpoints.token.client_credentials_disabled',
					__( 'The client_credentials grant type is not enabled.', 'oauth2' ),
					[ 'status' => WP_Http::BAD_REQUEST ]
				);
			}
			return $this->handle_client_credentials( $request );
		}

		$client = OAuth2\get_client( $request['client_id'] );
		if ( empty( $client ) ) {
			return new WP_Error(
				'oauth2.endpoints.token.exchange_token.invalid_client',
				/* translators: %s: client ID */
				sprintf( __( 'Client ID %s is invalid.', 'oauth2' ), $request['client_id'] ),
				[
					'status'    => WP_Http::BAD_REQUEST,
					'client_id' => $request['client_id'],
				]
			);
		}

		$auth_code = $client->get_authorization_code( $request['code'] );
		if ( is_wp_error( $auth_code ) ) {
			return $auth_code;
		}

		$is_valid = $auth_code->validate();
		if ( is_wp_error( $is_valid ) ) {
			// Invalid request, but code itself exists, so we should delete
			// (and silently ignore errors).
			$auth_code->delete();

			return $is_valid;
		}

		// Looks valid, delete the code and issue a token.
		$user = $auth_code->get_user();
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$did_delete = $auth_code->delete();
		if ( is_wp_error( $did_delete ) ) {
			return $did_delete;
		}

		$token = $client->issue_token( $user );
		if ( is_wp_error( $token ) ) {
			return $token;
		}

		$data = [
			'access_token' => $token->get_key(),
			'token_type'   => 'bearer',
		];
		return $data;
	}

	/**
	 * Handle client credentials grant type.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error Token data on success, or error on failure.
	 */
	private function handle_client_credentials( WP_REST_Request $request ) {
		// Extract client credentials from Authorization header or request body
		$credentials = $this->extract_client_credentials( $request );
		if ( is_wp_error( $credentials ) ) {
			return $credentials;
		}

		list( $client_id, $client_secret ) = $credentials;

		// Get the expected credentials from settings/filters.
		$expected_id     = OAuth2\Admin\Settings\get_client_id();
		$expected_secret = OAuth2\Admin\Settings\get_client_secret();

		if ( empty( $expected_id ) || empty( $expected_secret ) ) {
			return new WP_Error(
				'oauth2.endpoints.token.not_configured',
				__( 'Client credentials are not configured.', 'oauth2' ),
				[ 'status' => WP_Http::INTERNAL_SERVER_ERROR ]
			);
		}

		// Validate client ID and secret using timing-safe comparison.
		if ( ! hash_equals( $expected_id, $client_id )
			|| ! hash_equals( $expected_secret, $client_secret )
		) {
			return new WP_Error(
				'oauth2.endpoints.token.invalid_client',
				__( 'Client authentication failed.', 'oauth2' ),
				[ 'status' => WP_Http::UNAUTHORIZED ]
			);
		}

		// Look up a Client post for token storage.
		// First try matching by client_id slug, then fall back to the settings storage client.
		$client = OAuth2\get_client( $client_id );

		if ( empty( $client ) ) {
			$client = OAuth2\Admin\Settings\get_storage_client();
		}

		if ( empty( $client ) || is_wp_error( $client ) ) {
			return new WP_Error(
				'oauth2.endpoints.token.storage_not_configured',
				__( 'Client credentials storage is not configured.', 'oauth2' ),
				[ 'status' => WP_Http::INTERNAL_SERVER_ERROR ]
			);
		}

		// Create access token for the client (no user)
		$token = OAuth2\Tokens\Access_Token::create_for_client( $client );
		if ( is_wp_error( $token ) ) {
			return $token;
		}

		$ttl = apply_filters( 'oauth2.client_token_ttl', OAuth2\Tokens\Access_Token::DEFAULT_TTL );

		return [
			'access_token' => $token->get_key(),
			'token_type'   => 'bearer',
			'expires_in'   => $ttl,
		];
	}

	/**
	 * Extract client credentials from Authorization header or request body.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error Array with client_id and client_secret, or error.
	 */
	private function extract_client_credentials( WP_REST_Request $request ) {
		// Try from request body first (avoids conflict with proxy/HTTP basic auth headers)
		$client_id     = $request->get_param( 'client_id' );
		$client_secret = $request->get_param( 'client_secret' );

		if ( ! empty( $client_id ) && ! empty( $client_secret ) ) {
			return [ $client_id, $client_secret ];
		}

		// Fall back to Basic authentication from Authorization header
		$auth_header = $request->get_header( 'authorization' );

		if ( ! empty( $auth_header ) && stripos( $auth_header, 'Basic ' ) === 0 ) {
			$encoded = substr( $auth_header, 6 );
			$decoded = base64_decode( $encoded, true );

			if ( $decoded === false ) {
				return new WP_Error(
					'oauth2.endpoints.token.invalid_request',
					__( 'Invalid Authorization header.', 'oauth2' ),
					[ 'status' => WP_Http::BAD_REQUEST ]
				);
			}

			$parts = explode( ':', $decoded, 2 );
			if ( count( $parts ) !== 2 ) {
				return new WP_Error(
					'oauth2.endpoints.token.invalid_request',
					__( 'Invalid Authorization header format.', 'oauth2' ),
					[ 'status' => WP_Http::BAD_REQUEST ]
				);
			}

			return [ trim( $parts[0] ), trim( $parts[1] ) ];
		}

		return new WP_Error(
			'oauth2.endpoints.token.invalid_request',
			__( 'Client credentials not provided.', 'oauth2' ),
			[ 'status' => WP_Http::BAD_REQUEST ]
		);
	}
}
