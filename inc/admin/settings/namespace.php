<?php
/**
 * OAuth2 Settings Page.
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Admin\Settings;

use WP\OAuth2\Client;

const PAGE_SLUG = 'oauth2-settings';

/**
 * Bootstrap the settings page.
 */
function bootstrap() {
	add_action( 'admin_menu', __NAMESPACE__ . '\\register' );
	add_action( 'admin_init', __NAMESPACE__ . '\\register_settings' );
	add_action( 'admin_post_oauth2_regenerate_credentials', __NAMESPACE__ . '\\handle_regenerate' );
}

/**
 * Register the settings page under Settings menu.
 */
function register() {
	add_options_page(
		__( 'OAuth2 Settings', 'oauth2' ),
		__( 'OAuth2', 'oauth2' ),
		'manage_options',
		PAGE_SLUG,
		__NAMESPACE__ . '\\render_page'
	);
}

/**
 * Register settings, sections, and fields.
 */
function register_settings() {
	register_setting( 'oauth2_settings_group', 'oauth2_settings', [
		'type'              => 'array',
		'sanitize_callback' => __NAMESPACE__ . '\\sanitize_settings',
		'default'           => [
			'client_credentials_enabled' => false,
			'client_id'                  => '',
			'client_secret'              => '',
		],
	] );

	add_settings_section(
		'oauth2_client_credentials',
		__( 'Client Credentials Grant', 'oauth2' ),
		__NAMESPACE__ . '\\render_section_description',
		PAGE_SLUG
	);

	add_settings_field(
		'client_credentials_enabled',
		__( 'Enable Client Credentials', 'oauth2' ),
		__NAMESPACE__ . '\\render_enabled_field',
		PAGE_SLUG,
		'oauth2_client_credentials'
	);

	add_settings_field(
		'client_credentials_info',
		__( 'Client Credentials', 'oauth2' ),
		__NAMESPACE__ . '\\render_credentials_field',
		PAGE_SLUG,
		'oauth2_client_credentials'
	);
}

/**
 * Sanitize settings input.
 *
 * Auto-generates client_id and client_secret when enabling for the first time.
 *
 * @param array $input Raw input.
 * @return array Sanitized settings.
 */
function sanitize_settings( $input ) {
	$existing  = get_option( 'oauth2_settings', [] );
	$sanitized = [];

	$sanitized['client_credentials_enabled'] = ! empty( $input['client_credentials_enabled'] );

	// Preserve existing credentials and storage client post ID.
	$sanitized['client_id']            = ! empty( $existing['client_id'] ) ? $existing['client_id'] : '';
	$sanitized['client_secret']        = ! empty( $existing['client_secret'] ) ? $existing['client_secret'] : '';
	$sanitized['storage_client_post_id'] = ! empty( $existing['storage_client_post_id'] ) ? $existing['storage_client_post_id'] : 0;

	if ( $sanitized['client_credentials_enabled'] && empty( $sanitized['client_id'] ) ) {
		$client_id     = wp_generate_password( Client::CLIENT_ID_LENGTH, false );
		$client_secret = wp_generate_password( Client::CLIENT_SECRET_LENGTH, false );

		$post_id = create_storage_client( $client_id, $client_secret );
		if ( $post_id ) {
			$sanitized['client_id']              = $client_id;
			$sanitized['client_secret']          = $client_secret;
			$sanitized['storage_client_post_id'] = $post_id;
		}
	}

	return $sanitized;
}

/**
 * Render the section description.
 */
function render_section_description() {
	echo '<p>';
	esc_html_e(
		'Configure the Client Credentials grant type for machine-to-machine authentication. When enabled, applications can authenticate using a client ID and secret without user interaction.',
		'oauth2'
	);
	echo '</p>';
}

/**
 * Render the enable/disable checkbox field.
 */
function render_enabled_field() {
	$options = get_option( 'oauth2_settings', [] );
	$enabled = ! empty( $options['client_credentials_enabled'] );
	?>
	<label for="oauth2-cc-enabled">
		<input
			type="checkbox"
			id="oauth2-cc-enabled"
			name="oauth2_settings[client_credentials_enabled]"
			value="1"
			<?php checked( $enabled ); ?>
		/>
		<?php esc_html_e( 'Enable the Client Credentials grant type', 'oauth2' ); ?>
	</label>
	<p class="description">
		<?php esc_html_e( 'When disabled, client_credentials requests will be rejected. Existing authorization_code flows are not affected.', 'oauth2' ); ?>
	</p>
	<?php
}

/**
 * Render the credentials display field.
 */
function render_credentials_field() {
	$options       = get_option( 'oauth2_settings', [] );
	$client_id     = ! empty( $options['client_id'] ) ? $options['client_id'] : '';
	$client_secret = ! empty( $options['client_secret'] ) ? $options['client_secret'] : '';

	if ( empty( $client_id ) ) {
		echo '<p class="description">';
		esc_html_e( 'Enable client credentials above and save to auto-generate credentials.', 'oauth2' );
		echo '</p>';
		return;
	}

	$regenerate_url = wp_nonce_url(
		admin_url( 'admin-post.php?action=oauth2_regenerate_credentials' ),
		'oauth2_regenerate_credentials'
	);
	?>
	<table class="widefat fixed" style="max-width: 500px;">
		<tbody>
			<tr>
				<td><strong><?php esc_html_e( 'Client ID', 'oauth2' ); ?></strong></td>
				<td><code><?php echo esc_html( $client_id ); ?></code></td>
			</tr>
			<tr>
				<td><strong><?php esc_html_e( 'Client Secret', 'oauth2' ); ?></strong></td>
				<td><code><?php echo esc_html( $client_secret ); ?></code></td>
			</tr>
		</tbody>
	</table>

	<p>
		<a href="<?php echo esc_url( $regenerate_url ); ?>" class="button" onclick="return confirm('<?php echo esc_js( __( 'Are you sure? This will invalidate the current credentials.', 'oauth2' ) ); ?>');">
			<?php esc_html_e( 'Regenerate Credentials', 'oauth2' ); ?>
		</a>
	</p>

	<p class="description">
		<?php esc_html_e( 'Share these credentials with third-party applications. You can override them with filters in your theme or plugin:', 'oauth2' ); ?>
	</p>
	<pre style="background: #f0f0f0; padding: 10px; max-width: 500px; overflow-x: auto;">add_filter( 'oauth2.client_credentials.client_id', fn() => getenv( 'OAUTH2_CLIENT_ID' ) );
add_filter( 'oauth2.client_credentials.client_secret', fn() => getenv( 'OAUTH2_CLIENT_SECRET' ) );</pre>
	<?php
}

/**
 * Handle credential regeneration.
 */
function handle_regenerate() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to perform this action.', 'oauth2' ), 403 );
	}

	check_admin_referer( 'oauth2_regenerate_credentials' );

	$options       = get_option( 'oauth2_settings', [] );
	$client_id     = wp_generate_password( Client::CLIENT_ID_LENGTH, false );
	$client_secret = wp_generate_password( Client::CLIENT_SECRET_LENGTH, false );

	// Delete old storage client post if it exists.
	$old_post_id = ! empty( $options['storage_client_post_id'] ) ? (int) $options['storage_client_post_id'] : 0;
	if ( $old_post_id ) {
		wp_delete_post( $old_post_id, true );
	}

	// Create new storage client post.
	$post_id = create_storage_client( $client_id, $client_secret );

	$options['client_id']              = $client_id;
	$options['client_secret']          = $client_secret;
	$options['storage_client_post_id'] = $post_id ?: 0;

	update_option( 'oauth2_settings', $options );

	wp_safe_redirect( add_query_arg( 'regenerated', '1', admin_url( 'options-general.php?page=' . PAGE_SLUG ) ) );
	exit;
}

/**
 * Render the settings page.
 */
function render_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'OAuth2 Settings', 'oauth2' ); ?></h1>

		<?php if ( ! empty( $_GET['regenerated'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
			<div id="message" class="updated"><p><?php esc_html_e( 'Credentials regenerated successfully.', 'oauth2' ); ?></p></div>
		<?php endif; ?>

		<form method="post" action="options.php">
			<?php
			settings_fields( 'oauth2_settings_group' );
			do_settings_sections( PAGE_SLUG );
			submit_button();
			?>
		</form>
	</div>
	<?php
}

/**
 * Check whether the client credentials grant type is enabled.
 *
 * @return bool
 */
function is_client_credentials_enabled() {
	$options = get_option( 'oauth2_settings', [] );
	$enabled = ! empty( $options['client_credentials_enabled'] );

	/**
	 * Filter whether the client credentials grant type is enabled.
	 *
	 * @param bool $enabled Whether client credentials are enabled.
	 */
	return (bool) apply_filters( 'oauth2.client_credentials.enabled', $enabled );
}

/**
 * Get the client ID for client credentials validation.
 *
 * Returns the stored value by default. Use the filter to override with env vars.
 *
 * @return string
 */
function get_client_id() {
	$options   = get_option( 'oauth2_settings', [] );
	$client_id = ! empty( $options['client_id'] ) ? $options['client_id'] : '';

	/**
	 * Filter the client ID used for client credentials validation.
	 *
	 * @param string $client_id The client ID.
	 */
	return (string) apply_filters( 'oauth2.client_credentials.client_id', $client_id );
}

/**
 * Get the client secret for client credentials validation.
 *
 * Returns the stored value by default. Use the filter to override with env vars.
 *
 * @return string
 */
function get_client_secret() {
	$options       = get_option( 'oauth2_settings', [] );
	$client_secret = ! empty( $options['client_secret'] ) ? $options['client_secret'] : '';

	/**
	 * Filter the client secret used for client credentials validation.
	 *
	 * @param string $client_secret The client secret.
	 */
	return (string) apply_filters( 'oauth2.client_credentials.client_secret', $client_secret );
}

/**
 * Create a backing Client post for token storage.
 *
 * This internal Client post is used to store issued access tokens via post meta,
 * ensuring compatibility with the existing token lookup and authentication flow.
 *
 * @param string $client_id     The client ID (used as post slug).
 * @param string $client_secret The client secret.
 * @return int|false Post ID on success, false on failure.
 */
function create_storage_client( $client_id, $client_secret ) {
	$post_id = wp_insert_post( [
		'post_type'    => Client::POST_TYPE,
		'post_title'   => __( 'Client Credentials (System)', 'oauth2' ),
		'post_content' => __( 'Auto-generated client for client credentials grant. Managed via Settings > OAuth2.', 'oauth2' ),
		'post_name'    => $client_id,
		'post_status'  => 'publish',
	], true );

	if ( is_wp_error( $post_id ) ) {
		return false;
	}

	update_post_meta( $post_id, Client::CLIENT_SECRET_KEY, $client_secret );
	update_post_meta( $post_id, Client::TYPE_KEY, 'private' );
	update_post_meta( $post_id, '_oauth2_is_system_client', true );

	return $post_id;
}

/**
 * Get the storage Client instance for token creation.
 *
 * Used by the token endpoint when credentials are overridden via filters
 * and don't match the Client post slug directly.
 *
 * @return \WP\OAuth2\Client|null Client instance or null if not configured.
 */
function get_storage_client() {
	$options = get_option( 'oauth2_settings', [] );
	$post_id = ! empty( $options['storage_client_post_id'] ) ? (int) $options['storage_client_post_id'] : 0;

	if ( ! $post_id ) {
		return null;
	}

	return Client::get_by_post_id( $post_id );
}
