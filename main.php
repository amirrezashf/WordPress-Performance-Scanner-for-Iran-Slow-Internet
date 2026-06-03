/**
 * Plugin Name: Bad Domain Blocker Pro
 * Description: مسدودسازی دامنه‌ها، آی‌پی‌ها و الگوهای مشکل‌ساز برای جلوگیری از کندی وردپرس، همراه با لاگ، آمار، تشخیص منبع درخواست، ثبت درخواست‌های کند، هشدار دامنه‌های پرخطر و پاکسازی خودکار لاگ‌ها.
 * Version: 3.0.0
 * Author: Amirreza Shayesteh Far
 * Plugin URI: #
 * Author URI: #
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'BBD_OPTION_RULES', 'bbd_rules' );
define( 'BBD_OPTION_BLOCKED_LOGS', 'bbd_blocked_logs' );
define( 'BBD_OPTION_SLOW_LOGS', 'bbd_slow_logs' );
define( 'BBD_OPTION_SETTINGS', 'bbd_settings' );
define( 'BBD_MAX_BLOCKED_LOGS', 1000 );
define( 'BBD_MAX_SLOW_LOGS', 1000 );
define( 'BBD_MENU_SLUG', 'bad-domain-firewall' );
define( 'BBD_CRON_HOOK_DAILY_CLEANUP', 'bbd_daily_cleanup_logs' );

$GLOBALS['bbd_live_requests'] = array();

/**
 * فقط نقش administrator مجاز باشد
 */
function bbd_current_user_is_real_admin() {
	if ( ! is_user_logged_in() ) {
		return false;
	}

	$user = wp_get_current_user();

	if ( empty( $user->roles ) || ! is_array( $user->roles ) ) {
		return false;
	}

	return in_array( 'administrator', $user->roles, true );
}

/**
 * فعال‌سازی اولیه
 */
register_activation_hook( __FILE__, 'bbd_activate_plugin' );
function bbd_activate_plugin() {
	add_option( BBD_OPTION_RULES, array(), '', 'no' );
	add_option( BBD_OPTION_BLOCKED_LOGS, array(), '', 'no' );
	add_option( BBD_OPTION_SLOW_LOGS, array(), '', 'no' );
	add_option(
		BBD_OPTION_SETTINGS,
		array(
			'slow_threshold'         => 3,
			'danger_hits_threshold'  => 10,
			'danger_avg_threshold'   => 2.5,
			'log_retention_days'     => 90,
		),
		'',
		'no'
	);

	bbd_maybe_migrate_rules_structure();

	if ( ! wp_next_scheduled( BBD_CRON_HOOK_DAILY_CLEANUP ) ) {
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', BBD_CRON_HOOK_DAILY_CLEANUP );
	}
}

/**
 * غیرفعال‌سازی افزونه
 */
register_deactivation_hook( __FILE__, 'bbd_deactivate_plugin' );
function bbd_deactivate_plugin() {
	$timestamp = wp_next_scheduled( BBD_CRON_HOOK_DAILY_CLEANUP );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, BBD_CRON_HOOK_DAILY_CLEANUP );
	}
}

/**
 * مهاجرت ساختار قوانین
 * نسخه قدیمی: ['domain.com', '*.site.com']
 * نسخه جدید:
 * [
 *   [
 *     'rule' => 'domain.com',
 *     'enabled' => 1,
 *     'created_at' => '2026-03-09 12:00:00',
 *   ]
 * ]
 */
function bbd_maybe_migrate_rules_structure() {
	$rules = get_option( BBD_OPTION_RULES, array() );

	if ( ! is_array( $rules ) ) {
		update_option( BBD_OPTION_RULES, array(), false );
		return;
	}

	$needs_migration = false;

	foreach ( $rules as $item ) {
		if ( is_string( $item ) ) {
			$needs_migration = true;
			break;
		}
		if ( is_array( $item ) && ! isset( $item['rule'] ) ) {
			$needs_migration = true;
			break;
		}
	}

	if ( ! $needs_migration ) {
		return;
	}

	$new_rules = array();

	foreach ( $rules as $item ) {
		if ( is_string( $item ) ) {
			$rule = bbd_normalize_rule( $item );

			if ( '' === $rule ) {
				continue;
			}

			$new_rules[] = array(
				'rule'       => $rule,
				'enabled'    => 1,
				'created_at' => current_time( 'mysql' ),
			);
		} elseif ( is_array( $item ) && ! empty( $item['rule'] ) ) {
			$new_rules[] = array(
				'rule'       => bbd_normalize_rule( $item['rule'] ),
				'enabled'    => isset( $item['enabled'] ) ? (int) (bool) $item['enabled'] : 1,
				'created_at' => ! empty( $item['created_at'] ) ? $item['created_at'] : current_time( 'mysql' ),
			);
		}
	}

	update_option( BBD_OPTION_RULES, array_values( $new_rules ), false );
}

/**
 * تنظیمات
 */
function bbd_get_settings() {
	$settings = get_option( BBD_OPTION_SETTINGS, array() );
	$settings = wp_parse_args(
		$settings,
		array(
			'slow_threshold'         => 3,
			'danger_hits_threshold'  => 10,
			'danger_avg_threshold'   => 2.5,
			'log_retention_days'     => 90,
		)
	);

	$settings['slow_threshold']        = max( 1, (float) $settings['slow_threshold'] );
	$settings['danger_hits_threshold'] = max( 1, absint( $settings['danger_hits_threshold'] ) );
	$settings['danger_avg_threshold']  = max( 0.5, (float) $settings['danger_avg_threshold'] );
	$settings['log_retention_days']    = max( 1, absint( $settings['log_retention_days'] ) );

	return $settings;
}

/**
 * همه قوانین
 */
function bbd_get_rules() {
	$rules = get_option( BBD_OPTION_RULES, array() );

	if ( ! is_array( $rules ) ) {
		return array();
	}

	$normalized = array();

	foreach ( $rules as $item ) {
		if ( is_string( $item ) ) {
			$item = array(
				'rule'       => bbd_normalize_rule( $item ),
				'enabled'    => 1,
				'created_at' => current_time( 'mysql' ),
			);
		}

		if ( ! is_array( $item ) || empty( $item['rule'] ) ) {
			continue;
		}

		$rule = bbd_normalize_rule( $item['rule'] );
		if ( '' === $rule ) {
			continue;
		}

		$normalized[] = array(
			'rule'       => $rule,
			'enabled'    => isset( $item['enabled'] ) ? (int) (bool) $item['enabled'] : 1,
			'created_at' => ! empty( $item['created_at'] ) ? $item['created_at'] : current_time( 'mysql' ),
		);
	}

	return array_values( $normalized );
}

/**
 * فقط قوانین فعال
 */
function bbd_get_enabled_rules() {
	$rules   = bbd_get_rules();
	$enabled = array();

	foreach ( $rules as $item ) {
		if ( ! empty( $item['enabled'] ) ) {
			$enabled[] = $item;
		}
	}

	return $enabled;
}

function bbd_find_rule_index( $needle_rule ) {
	$rules = bbd_get_rules();

	foreach ( $rules as $index => $item ) {
		if ( isset( $item['rule'] ) && $item['rule'] === $needle_rule ) {
			return $index;
		}
	}

	return false;
}

function bbd_get_logs( $type = 'blocked' ) {
	$key  = ( 'slow' === $type ) ? BBD_OPTION_SLOW_LOGS : BBD_OPTION_BLOCKED_LOGS;
	$logs = get_option( $key, array() );
	return is_array( $logs ) ? $logs : array();
}

function bbd_save_logs( $logs, $type = 'blocked' ) {
	$key   = ( 'slow' === $type ) ? BBD_OPTION_SLOW_LOGS : BBD_OPTION_BLOCKED_LOGS;
	$limit = ( 'slow' === $type ) ? BBD_MAX_SLOW_LOGS : BBD_MAX_BLOCKED_LOGS;

	if ( ! is_array( $logs ) ) {
		$logs = array();
	}

	$logs = array_values( $logs );
	$logs = bbd_prune_logs_by_retention( $logs );
	$logs = array_slice( $logs, 0, $limit );

	update_option( $key, $logs, false );
}

function bbd_push_log( $entry, $type = 'blocked' ) {
	$logs = bbd_get_logs( $type );
	array_unshift( $logs, $entry );
	bbd_save_logs( $logs, $type );
}

/**
 * پاکسازی لاگ‌ها بر اساس تعداد روز
 */
function bbd_prune_logs_by_retention( $logs ) {
	if ( ! is_array( $logs ) || empty( $logs ) ) {
		return array();
	}

	$settings      = bbd_get_settings();
	$retention_days = max( 1, absint( $settings['log_retention_days'] ) );
	$threshold_ts   = current_time( 'timestamp' ) - ( $retention_days * DAY_IN_SECONDS );
	$pruned         = array();

	foreach ( $logs as $log ) {
		if ( empty( $log['time'] ) ) {
			continue;
		}

		$log_ts = strtotime( $log['time'] );
		if ( ! $log_ts ) {
			continue;
		}

		if ( $log_ts >= $threshold_ts ) {
			$pruned[] = $log;
		}
	}

	return array_values( $pruned );
}

/**
 * کرون روزانه پاکسازی لاگ‌ها
 */
add_action( BBD_CRON_HOOK_DAILY_CLEANUP, 'bbd_cleanup_logs_cron' );
function bbd_cleanup_logs_cron() {
	$blocked_logs = bbd_get_logs( 'blocked' );
	$slow_logs    = bbd_get_logs( 'slow' );

	update_option( BBD_OPTION_BLOCKED_LOGS, bbd_prune_logs_by_retention( $blocked_logs ), false );
	update_option( BBD_OPTION_SLOW_LOGS, bbd_prune_logs_by_retention( $slow_logs ), false );
}

/**
 * نرمال‌سازی قانون
 */
function bbd_normalize_rule( $rule ) {
	$rule = trim( wp_strip_all_tags( (string) $rule ) );
	$rule = strtolower( $rule );

	if ( '' === $rule ) {
		return '';
	}

	$rule = preg_replace( '#^https?://#i', '', $rule );
	$rule = preg_replace( '#^//#', '', $rule );
	$rule = trim( $rule );
	$rule = trim( $rule, '/' );

	return $rule;
}

/**
 * تشخیص نوع قانون
 */
function bbd_detect_rule_type( $rule ) {
	if ( filter_var( $rule, FILTER_VALIDATE_IP ) ) {
		return 'آی‌پی';
	}

	if ( false !== strpos( $rule, '*' ) ) {
		return 'الگو';
	}

	if ( false !== strpos( $rule, '/' ) ) {
		return 'مسیر / نشانی';
	}

	return 'دامنه';
}

/**
 * تبدیل wildcard به regex
 */
function bbd_wildcard_to_regex( $pattern ) {
	$quoted = preg_quote( $pattern, '#' );
	$regex  = str_replace( '\*', '.*', $quoted );
	return '#^' . $regex . '$#i';
}

/**
 * بررسی انطباق قانون با درخواست
 */
function bbd_rule_matches( $rule, $url, $host ) {
	$rule = bbd_normalize_rule( $rule );
	$url  = strtolower( (string) $url );
	$host = strtolower( (string) $host );

	if ( '' === $rule || '' === $url ) {
		return false;
	}

	if ( filter_var( $rule, FILTER_VALIDATE_IP ) ) {
		return $host === $rule;
	}

	if ( false !== strpos( $rule, '*' ) ) {
		$regex = bbd_wildcard_to_regex( $rule );

		if ( preg_match( $regex, $host ) ) {
			return true;
		}

		if ( preg_match( $regex, $url ) ) {
			return true;
		}

		if ( 0 === strpos( $rule, '*.' ) ) {
			$base = substr( $rule, 2 );
			if ( $host === $base || preg_match( '#(^|\.)' . preg_quote( $base, '#' ) . '$#i', $host ) ) {
				return true;
			}
		}

		return false;
	}

	if ( false !== strpos( $rule, '/' ) ) {
		return false !== strpos( $url, $rule );
	}

	if ( $host === $rule ) {
		return true;
	}

	if ( substr( $host, - strlen( '.' . $rule ) ) === '.' . $rule ) {
		return true;
	}

	if ( false !== strpos( $url, $rule ) ) {
		return true;
	}

	return false;
}

/**
 * تشخیص منبع درخواست‌دهنده
 */
function bbd_detect_request_source() {
	$backtrace = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 40 );

	if ( empty( $backtrace ) || ! is_array( $backtrace ) ) {
		return 'نامشخص';
	}

	$plugin_dir    = wp_normalize_path( WP_PLUGIN_DIR );
	$mu_plugin_dir = defined( 'WPMU_PLUGIN_DIR' ) ? wp_normalize_path( WPMU_PLUGIN_DIR ) : '';
	$theme_dir     = wp_normalize_path( get_theme_root() );
	$core_includes = wp_normalize_path( ABSPATH . WPINC );
	$core_admin    = wp_normalize_path( ABSPATH . 'wp-admin' );
	$self_file     = wp_normalize_path( __FILE__ );

	foreach ( $backtrace as $frame ) {
		if ( empty( $frame['file'] ) ) {
			continue;
		}

		$file = wp_normalize_path( $frame['file'] );

		if ( false !== strpos( $file, $self_file ) ) {
			continue;
		}

		if ( $plugin_dir && 0 === strpos( $file, $plugin_dir ) ) {
			$relative = ltrim( substr( $file, strlen( $plugin_dir ) ), '/' );
			$parts    = explode( '/', $relative );
			$name     = ! empty( $parts[0] ) ? $parts[0] : basename( $file );
			return 'افزونه: ' . $name;
		}

		if ( $mu_plugin_dir && 0 === strpos( $file, $mu_plugin_dir ) ) {
			$relative = ltrim( substr( $file, strlen( $mu_plugin_dir ) ), '/' );
			$parts    = explode( '/', $relative );
			$name     = ! empty( $parts[0] ) ? $parts[0] : basename( $file );
			return 'افزونه mu: ' . $name;
		}

		if ( $theme_dir && 0 === strpos( $file, $theme_dir ) ) {
			$relative = ltrim( substr( $file, strlen( $theme_dir ) ), '/' );
			$parts    = explode( '/', $relative );
			$name     = ! empty( $parts[0] ) ? $parts[0] : basename( $file );
			return 'پوسته: ' . $name;
		}

		if ( 0 === strpos( $file, $core_includes ) || 0 === strpos( $file, $core_admin ) ) {
			return 'هسته وردپرس';
		}
	}

	return 'نامشخص';
}

/**
 * تشخیص ناحیه درخواست
 */
function bbd_detect_request_area() {
	if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
		return 'رست';
	}

	if ( wp_doing_ajax() ) {
		return 'ای‌جکس';
	}

	if ( wp_doing_cron() ) {
		return 'کرون';
	}

	if ( is_admin() ) {
		return 'پیشخوان';
	}

	return 'فرانت';
}

/**
 * ابزارهای آماری
 */
function bbd_group_counts_by_key( $logs, $key ) {
	$counts = array();

	foreach ( $logs as $log ) {
		if ( empty( $log[ $key ] ) ) {
			continue;
		}

		$index = $log[ $key ];

		if ( ! isset( $counts[ $index ] ) ) {
			$counts[ $index ] = 0;
		}

		$counts[ $index ]++;
	}

	arsort( $counts );

	return $counts;
}

function bbd_get_top_slow_hosts( $logs ) {
	$data = array();

	foreach ( $logs as $log ) {
		$host = ! empty( $log['host'] ) ? $log['host'] : 'نامشخص';
		$time = isset( $log['elapsed'] ) ? (float) $log['elapsed'] : 0;

		if ( ! isset( $data[ $host ] ) ) {
			$data[ $host ] = array(
				'count' => 0,
				'sum'   => 0,
				'max'   => 0,
			);
		}

		$data[ $host ]['count']++;
		$data[ $host ]['sum'] += $time;

		if ( $time > $data[ $host ]['max'] ) {
			$data[ $host ]['max'] = $time;
		}
	}

	foreach ( $data as $host => $row ) {
		$data[ $host ]['avg'] = $row['count'] ? round( $row['sum'] / $row['count'], 2 ) : 0;
	}

	uasort(
		$data,
		function ( $a, $b ) {
			if ( $a['count'] === $b['count'] ) {
				return $b['avg'] <=> $a['avg'];
			}
			return $b['count'] <=> $a['count'];
		}
	);

	return $data;
}

/**
 * فقط لاگ‌های کندی که هنوز بلاک نشده‌اند
 */
function bbd_get_unblocked_slow_logs() {
	$enabled_rules = bbd_get_enabled_rules();
	$slow_logs     = bbd_get_logs( 'slow' );

	if ( empty( $slow_logs ) ) {
		return array();
	}

	$filtered = array();

	foreach ( $slow_logs as $log ) {
		$url  = ! empty( $log['url'] ) ? $log['url'] : '';
		$host = ! empty( $log['host'] ) ? $log['host'] : '';

		$is_blocked = false;

		foreach ( $enabled_rules as $rule_item ) {
			if ( empty( $rule_item['rule'] ) ) {
				continue;
			}

			if ( bbd_rule_matches( $rule_item['rule'], $url, $host ) ) {
				$is_blocked = true;
				break;
			}
		}

		if ( ! $is_blocked ) {
			$filtered[] = $log;
		}
	}

	return $filtered;
}

/**
 * دامنه‌های پرخطر از میان کندهای بلاک‌نشده در 24 ساعت اخیر
 */
function bbd_get_danger_domains( $logs ) {
	if ( empty( $logs ) || ! is_array( $logs ) ) {
		return array();
	}

	$settings          = bbd_get_settings();
	$hits_threshold    = (int) $settings['danger_hits_threshold'];
	$avg_threshold     = (float) $settings['danger_avg_threshold'];
	$since_timestamp   = current_time( 'timestamp' ) - DAY_IN_SECONDS;
	$data              = array();

	foreach ( $logs as $log ) {
		if ( empty( $log['host'] ) || empty( $log['time'] ) ) {
			continue;
		}

		$log_ts = strtotime( $log['time'] );
		if ( ! $log_ts || $log_ts < $since_timestamp ) {
			continue;
		}

		$host = $log['host'];
		$time = isset( $log['elapsed'] ) ? (float) $log['elapsed'] : 0;

		if ( ! isset( $data[ $host ] ) ) {
			$data[ $host ] = array(
				'count' => 0,
				'sum'   => 0,
				'max'   => 0,
			);
		}

		$data[ $host ]['count']++;
		$data[ $host ]['sum'] += $time;
		if ( $time > $data[ $host ]['max'] ) {
			$data[ $host ]['max'] = $time;
		}
	}

	$output = array();

	foreach ( $data as $host => $row ) {
		$avg = $row['count'] ? round( $row['sum'] / $row['count'], 2 ) : 0;

		if ( $row['count'] >= $hits_threshold || $avg >= $avg_threshold ) {
			$output[ $host ] = array(
				'count' => $row['count'],
				'avg'   => $avg,
				'max'   => round( $row['max'], 2 ),
			);
		}
	}

	uasort(
		$output,
		function( $a, $b ) {
			if ( $a['count'] === $b['count'] ) {
				return $b['avg'] <=> $a['avg'];
			}
			return $b['count'] <=> $a['count'];
		}
	);

	return $output;
}

/**
 * رهگیری شروع درخواست‌ها
 */
add_filter( 'http_request_args', 'bbd_track_http_request_start', 1, 2 );
function bbd_track_http_request_start( $args, $url ) {
	$key = wp_generate_uuid4();

	$args['_bbd_request_key'] = $key;

	$GLOBALS['bbd_live_requests'][ $key ] = array(
		'start'  => microtime( true ),
		'url'    => $url,
		'source' => bbd_detect_request_source(),
		'area'   => bbd_detect_request_area(),
		'method' => ! empty( $args['method'] ) ? strtoupper( $args['method'] ) : 'GET',
	);

	return $args;
}

/**
 * بلاک کردن درخواست‌ها
 */
add_filter( 'pre_http_request', 'bbd_pre_http_request_blocker', 99, 3 );
function bbd_pre_http_request_blocker( $pre, $args, $url ) {
	$enabled_rules = bbd_get_enabled_rules();

	if ( empty( $enabled_rules ) || empty( $url ) ) {
		return false;
	}

	$host = wp_parse_url( $url, PHP_URL_HOST );
	$host = strtolower( (string) $host );

	foreach ( $enabled_rules as $rule_item ) {
		if ( empty( $rule_item['rule'] ) ) {
			continue;
		}

		$rule = $rule_item['rule'];

		if ( bbd_rule_matches( $rule, $url, $host ) ) {
			$key   = ! empty( $args['_bbd_request_key'] ) ? $args['_bbd_request_key'] : '';
			$track = ( $key && ! empty( $GLOBALS['bbd_live_requests'][ $key ] ) ) ? $GLOBALS['bbd_live_requests'][ $key ] : array();

			bbd_push_log(
				array(
					'time'         => current_time( 'mysql' ),
					'url'          => esc_url_raw( $url ),
					'host'         => $host,
					'rule'         => $rule,
					'source'       => ! empty( $track['source'] ) ? $track['source'] : bbd_detect_request_source(),
					'area'         => ! empty( $track['area'] ) ? $track['area'] : bbd_detect_request_area(),
					'method'       => ! empty( $track['method'] ) ? $track['method'] : 'GET',
					'user_id'      => get_current_user_id(),
					'request_type' => 'blocked',
				),
				'blocked'
			);

			if ( $key && isset( $GLOBALS['bbd_live_requests'][ $key ] ) ) {
				unset( $GLOBALS['bbd_live_requests'][ $key ] );
			}

			return new WP_Error( 'blocked_domain', 'This request has been blocked.' );
		}
	}

	return false;
}

/**
 * ثبت درخواست‌های کند
 */
add_action( 'http_api_debug', 'bbd_log_slow_requests', 10, 5 );
function bbd_log_slow_requests( $response, $context, $class, $args, $url ) {
	if ( 'response' !== $context ) {
		return;
	}

	$key = ! empty( $args['_bbd_request_key'] ) ? $args['_bbd_request_key'] : '';

	if ( ! $key || empty( $GLOBALS['bbd_live_requests'][ $key ] ) ) {
		return;
	}

	$track = $GLOBALS['bbd_live_requests'][ $key ];
	unset( $GLOBALS['bbd_live_requests'][ $key ] );

	$elapsed   = microtime( true ) - (float) $track['start'];
	$settings  = bbd_get_settings();
	$threshold = (float) $settings['slow_threshold'];

	if ( $elapsed < $threshold ) {
		return;
	}

	$host = wp_parse_url( $url, PHP_URL_HOST );
	$host = strtolower( (string) $host );

	$status_code = '';
	$result_text = 'پاسخ نامشخص';

	if ( is_wp_error( $response ) ) {
		$result_text = 'خطا: ' . $response->get_error_message();
	} elseif ( is_array( $response ) && isset( $response['response']['code'] ) ) {
		$status_code = (string) $response['response']['code'];
		$result_text = 'کد ' . $status_code;
	}

	bbd_push_log(
		array(
			'time'        => current_time( 'mysql' ),
			'url'         => esc_url_raw( $url ),
			'host'        => $host,
			'elapsed'     => round( $elapsed, 3 ),
			'source'      => ! empty( $track['source'] ) ? $track['source'] : 'نامشخص',
			'area'        => ! empty( $track['area'] ) ? $track['area'] : 'نامشخص',
			'method'      => ! empty( $track['method'] ) ? $track['method'] : 'GET',
			'status_code' => $status_code,
			'result'      => $result_text,
			'user_id'     => get_current_user_id(),
		),
		'slow'
	);
}

/**
 * منوی مدیریت - فقط administrator
 */
add_action( 'admin_menu', 'bbd_register_admin_menu' );
function bbd_register_admin_menu() {
	if ( ! bbd_current_user_is_real_admin() ) {
		return;
	}

	add_menu_page(
		'فایروال درخواست‌های خارجی',
		'فایروال درخواست‌ها',
		'read',
		BBD_MENU_SLUG,
		'bbd_admin_page',
		'dashicons-shield-alt',
		80
	);
}

/**
 * لینک تنظیمات پلاگین - فقط administrator
 */
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'bbd_add_settings_link' );
function bbd_add_settings_link( $links ) {
	if ( ! bbd_current_user_is_real_admin() ) {
		return $links;
	}

	$settings_url = admin_url( 'admin.php?page=' . BBD_MENU_SLUG );
	array_unshift( $links, '<a href="' . esc_url( $settings_url ) . '">تنظیمات</a>' );

	return $links;
}

/**
 * جلوگیری از دسترسی مستقیم
 */
add_action( 'admin_init', 'bbd_protect_admin_page_access', 1 );
function bbd_protect_admin_page_access() {
	if ( ! is_admin() ) {
		return;
	}

	$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';

	if ( BBD_MENU_SLUG !== $page ) {
		return;
	}

	if ( ! bbd_current_user_is_real_admin() ) {
		wp_die( 'شما اجازه دسترسی به این صفحه را ندارید.' );
	}
}

/**
 * پردازش فرم‌ها
 */
add_action( 'admin_init', 'bbd_handle_admin_actions' );
function bbd_handle_admin_actions() {
	if ( ! is_admin() || ! bbd_current_user_is_real_admin() ) {
		return;
	}

	if ( empty( $_POST['bbd_action'] ) ) {
		return;
	}

	$action = sanitize_text_field( wp_unslash( $_POST['bbd_action'] ) );

	if ( ! isset( $_POST['bbd_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['bbd_nonce'] ) ), 'bbd_admin_action' ) ) {
		return;
	}

	switch ( $action ) {
		case 'add_rule':
			$rule = isset( $_POST['bbd_rule'] ) ? bbd_normalize_rule( wp_unslash( $_POST['bbd_rule'] ) ) : '';

			if ( '' !== $rule ) {
				$rules = bbd_get_rules();
				$exists = false;

				foreach ( $rules as $item ) {
					if ( isset( $item['rule'] ) && $item['rule'] === $rule ) {
						$exists = true;
						break;
					}
				}

				if ( ! $exists ) {
					$rules[] = array(
						'rule'       => $rule,
						'enabled'    => 1,
						'created_at' => current_time( 'mysql' ),
					);
					update_option( BBD_OPTION_RULES, array_values( $rules ), false );
				}
			}
			break;

		case 'delete_rule':
			$rule  = isset( $_POST['bbd_rule'] ) ? bbd_normalize_rule( wp_unslash( $_POST['bbd_rule'] ) ) : '';
			$rules = bbd_get_rules();

			$rules = array_values(
				array_filter(
					$rules,
					function ( $item ) use ( $rule ) {
						return empty( $item['rule'] ) || $item['rule'] !== $rule;
					}
				)
			);

			update_option( BBD_OPTION_RULES, $rules, false );
			break;

		case 'toggle_rule':
			$rule  = isset( $_POST['bbd_rule'] ) ? bbd_normalize_rule( wp_unslash( $_POST['bbd_rule'] ) ) : '';
			$rules = bbd_get_rules();
			$index = bbd_find_rule_index( $rule );

			if ( false !== $index && isset( $rules[ $index ] ) ) {
				$rules[ $index ]['enabled'] = empty( $rules[ $index ]['enabled'] ) ? 1 : 0;
				update_option( BBD_OPTION_RULES, array_values( $rules ), false );
			}
			break;

		case 'save_settings':
			$slow_threshold        = isset( $_POST['slow_threshold'] ) ? max( 1, (float) $_POST['slow_threshold'] ) : 3;
			$danger_hits_threshold = isset( $_POST['danger_hits_threshold'] ) ? max( 1, absint( $_POST['danger_hits_threshold'] ) ) : 10;
			$danger_avg_threshold  = isset( $_POST['danger_avg_threshold'] ) ? max( 0.5, (float) $_POST['danger_avg_threshold'] ) : 2.5;

			update_option(
				BBD_OPTION_SETTINGS,
				array(
					'slow_threshold'         => $slow_threshold,
					'danger_hits_threshold'  => $danger_hits_threshold,
					'danger_avg_threshold'   => $danger_avg_threshold,
					'log_retention_days'     => 90,
				),
				false
			);
			break;

		case 'clear_blocked_logs':
			update_option( BBD_OPTION_BLOCKED_LOGS, array(), false );
			break;

		case 'clear_slow_logs':
			update_option( BBD_OPTION_SLOW_LOGS, array(), false );
			break;

		case 'quick_block_host':
			$host = isset( $_POST['bbd_host'] ) ? bbd_normalize_rule( wp_unslash( $_POST['bbd_host'] ) ) : '';
			if ( '' !== $host ) {
				$rules = bbd_get_rules();
				$exists = false;

				foreach ( $rules as $item ) {
					if ( isset( $item['rule'] ) && $item['rule'] === $host ) {
						$exists = true;
						break;
					}
				}

				if ( ! $exists ) {
					$rules[] = array(
						'rule'       => $host,
						'enabled'    => 1,
						'created_at' => current_time( 'mysql' ),
					);
					update_option( BBD_OPTION_RULES, array_values( $rules ), false );
				}
			}
			break;
	}
}

/**
 * رسم نوارهای آماری
 */
function bbd_render_stat_bars( $items, $suffix = '' ) {
	if ( empty( $items ) ) {
		echo '<p>داده‌ای برای نمایش وجود ندارد.</p>';
		return;
	}

	$max = max( $items );

	echo '<div class="bbd-bars">';

	$counter = 0;
	foreach ( $items as $label => $value ) {
		$counter++;
		if ( $counter > 8 ) {
			break;
		}

		$percent = $max > 0 ? round( ( $value / $max ) * 100 ) : 0;

		echo '<div class="bbd-bar-row">';
		echo '<div class="bbd-bar-label">' . esc_html( $label ) . '</div>';
		echo '<div class="bbd-bar-track"><span class="bbd-bar-fill" style="width:' . esc_attr( $percent ) . '%"></span></div>';
		echo '<div class="bbd-bar-value">' . esc_html( $value . $suffix ) . '</div>';
		echo '</div>';
	}

	echo '</div>';
}

/**
 * صفحه مدیریت
 */
function bbd_admin_page() {
	if ( ! bbd_current_user_is_real_admin() ) {
		return;
	}

	$tab                 = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'dashboard';
	$rules               = bbd_get_rules();
	$blocked_logs        = bbd_get_logs( 'blocked' );
	$unblocked_slow_logs = bbd_get_unblocked_slow_logs();
	$settings            = bbd_get_settings();

	$blocked_by_host        = bbd_group_counts_by_key( $blocked_logs, 'host' );
	$blocked_by_source      = bbd_group_counts_by_key( $blocked_logs, 'source' );
	$unblocked_slow_sources = bbd_group_counts_by_key( $unblocked_slow_logs, 'source' );
	$unblocked_slow_stats   = bbd_get_top_slow_hosts( $unblocked_slow_logs );
	$danger_domains         = bbd_get_danger_domains( $unblocked_slow_logs );

	$unblocked_slow_bar_data = array();
	foreach ( $unblocked_slow_stats as $host => $row ) {
		$unblocked_slow_bar_data[ $host ] = $row['count'];
	}
	?>
	<div class="wrap bbd-wrap">
		<h1>فایروال درخواست‌های خارجی</h1>

		<h2 class="nav-tab-wrapper">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . BBD_MENU_SLUG . '&tab=dashboard' ) ); ?>" class="nav-tab <?php echo ( 'dashboard' === $tab ) ? 'nav-tab-active' : ''; ?>">داشبورد</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . BBD_MENU_SLUG . '&tab=rules' ) ); ?>" class="nav-tab <?php echo ( 'rules' === $tab ) ? 'nav-tab-active' : ''; ?>">قوانین مسدودسازی</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . BBD_MENU_SLUG . '&tab=blocked_activity' ) ); ?>" class="nav-tab <?php echo ( 'blocked_activity' === $tab ) ? 'nav-tab-active' : ''; ?>">فعالیت دامنه‌های مسدودشده</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . BBD_MENU_SLUG . '&tab=slow_requests' ) ); ?>" class="nav-tab <?php echo ( 'slow_requests' === $tab ) ? 'nav-tab-active' : ''; ?>">درخواست‌های کند بلاک‌نشده</a>
		</h2>

		<?php if ( 'dashboard' === $tab ) : ?>
			<div class="bbd-cards">
				<div class="bbd-card">
					<div class="bbd-card-title">تعداد قوانین</div>
					<div class="bbd-card-value"><?php echo esc_html( count( $rules ) ); ?></div>
				</div>
				<div class="bbd-card">
					<div class="bbd-card-title">درخواست‌های بلاک‌شده</div>
					<div class="bbd-card-value"><?php echo esc_html( count( $blocked_logs ) ); ?></div>
				</div>
				<div class="bbd-card">
					<div class="bbd-card-title">درخواست‌های کند بلاک‌نشده</div>
					<div class="bbd-card-value"><?php echo esc_html( count( $unblocked_slow_logs ) ); ?></div>
				</div>
				<div class="bbd-card">
					<div class="bbd-card-title">پاکسازی خودکار لاگ‌ها</div>
					<div class="bbd-card-value"><?php echo esc_html( $settings['log_retention_days'] ); ?> روز</div>
				</div>
			</div>

			<?php if ( ! empty( $danger_domains ) ) : ?>
				<div class="bbd-alert-panel">
					<h3>هشدار دامنه‌های پرخطر در ۲۴ ساعت اخیر</h3>
					<table class="widefat striped">
						<thead>
							<tr>
								<th>دامنه / آی‌پی</th>
								<th>تعداد درخواست کند</th>
								<th>میانگین</th>
								<th>بیشترین زمان</th>
								<th>عملیات</th>
							</tr>
						</thead>
						<tbody>
							<?php
							$counter = 0;
							foreach ( $danger_domains as $host => $row ) :
								$counter++;
								if ( $counter > 10 ) {
									break;
								}
								?>
								<tr>
									<td><code><?php echo esc_html( $host ); ?></code></td>
									<td><?php echo esc_html( $row['count'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( $row['avg'], 2 ) ); ?> ثانیه</td>
									<td><?php echo esc_html( number_format_i18n( $row['max'], 2 ) ); ?> ثانیه</td>
									<td>
										<form method="post" style="display:inline;">
											<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
											<input type="hidden" name="bbd_action" value="quick_block_host">
											<input type="hidden" name="bbd_host" value="<?php echo esc_attr( $host ); ?>">
											<button type="submit" class="button button-primary">افزودن به لیست مسدود</button>
										</form>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<p class="description">
						دامنه‌های پرخطر بر اساس لاگ‌های ۲۴ ساعت اخیر و با توجه به تعداد درخواست کند یا میانگین زمان بالا شناسایی می‌شوند.
					</p>
				</div>
			<?php endif; ?>

			<div class="bbd-grid">
				<div class="bbd-panel">
					<h3>بیشترین دامنه‌ها یا آی‌پی‌های مسدودشده</h3>
					<?php bbd_render_stat_bars( $blocked_by_host ); ?>
				</div>

				<div class="bbd-panel">
					<h3>بیشترین دامنه‌های کند بلاک‌نشده</h3>
					<?php bbd_render_stat_bars( $unblocked_slow_bar_data ); ?>
				</div>
			</div>

			<div class="bbd-grid">
				<div class="bbd-panel">
					<h3>منابع درخواست در بخش مسدودشده‌ها</h3>
					<?php bbd_render_stat_bars( $blocked_by_source ); ?>
				</div>

				<div class="bbd-panel">
					<h3>منابع درخواست در بخش کندهای بلاک‌نشده</h3>
					<?php bbd_render_stat_bars( $unblocked_slow_sources ); ?>
				</div>
			</div>

			<div class="bbd-grid">
				<div class="bbd-panel">
					<h3>تنظیمات اصلی</h3>
					<form method="post">
						<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
						<input type="hidden" name="bbd_action" value="save_settings">

						<table class="form-table">
							<tr>
								<th scope="row">آستانه ثبت درخواست کند</th>
								<td>
									<input type="number" min="1" step="0.1" name="slow_threshold" value="<?php echo esc_attr( $settings['slow_threshold'] ); ?>" class="small-text"> ثانیه
								</td>
							</tr>
							<tr>
								<th scope="row">آستانه تعداد برای هشدار پرخطر</th>
								<td>
									<input type="number" min="1" name="danger_hits_threshold" value="<?php echo esc_attr( $settings['danger_hits_threshold'] ); ?>" class="small-text"> درخواست در ۲۴ ساعت اخیر
								</td>
							</tr>
							<tr>
								<th scope="row">آستانه میانگین زمان برای هشدار پرخطر</th>
								<td>
									<input type="number" min="0.5" step="0.1" name="danger_avg_threshold" value="<?php echo esc_attr( $settings['danger_avg_threshold'] ); ?>" class="small-text"> ثانیه
								</td>
							</tr>
							<tr>
								<th scope="row">پاکسازی خودکار لاگ‌ها</th>
								<td>
									<strong>فعال</strong> — لاگ‌های قدیمی‌تر از <strong>۹۰ روز</strong> به‌صورت خودکار روزانه پاک می‌شوند.
								</td>
							</tr>
						</table>

						<p><button type="submit" class="button button-primary">ذخیره تنظیمات</button></p>
					</form>
				</div>

				<div class="bbd-panel">
					<h3>راهنمای سریع</h3>
					<p>در تب «قوانین مسدودسازی» می‌توانی دامنه، آی‌پی، الگو یا مسیر خاص ثبت کنی.</p>
					<p>هر قانون را می‌توانی بدون حذف کامل، موقتاً غیرفعال کنی.</p>
					<p>در داشبورد، دامنه‌های پرخطرِ ۲۴ ساعت اخیر به‌صورت جداگانه هشدار داده می‌شوند.</p>
				</div>
			</div>

		<?php elseif ( 'rules' === $tab ) : ?>

			<div class="bbd-panel">
				<h3>افزودن قانون جدید</h3>
				<form method="post" class="bbd-add-form">
					<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
					<input type="hidden" name="bbd_action" value="add_rule">

					<input type="text" name="bbd_rule" class="regular-text" placeholder="مثال: yithemes.com یا *.yithemes.com یا 34.120.12.1 یا api.domain.com/path">
					<button type="submit" class="button button-primary">افزودن</button>
				</form>

				<div class="bbd-help-box">
					<strong>نمونه‌ها:</strong><br>
					دامنه: <code>yithemes.com</code><br>
					زیر دامنه با الگو: <code>*.yithemes.com</code><br>
					آی‌پی: <code>34.120.12.1</code><br>
					مسیر خاص: <code>api.domain.com/license</code>
				</div>
			</div>

			<div class="bbd-panel">
				<h3>لیست قوانین ثبت‌شده</h3>

				<table class="widefat striped">
					<thead>
						<tr>
							<th>قانون</th>
							<th>نوع</th>
							<th>وضعیت</th>
							<th>تاریخ ثبت</th>
							<th>عملیات</th>
						</tr>
					</thead>
					<tbody>
					<?php if ( empty( $rules ) ) : ?>
						<tr>
							<td colspan="5" class="bbd-empty">هنوز قانونی ثبت نشده است.</td>
						</tr>
					<?php else : ?>
						<?php foreach ( $rules as $item ) : ?>
							<?php
							$rule       = isset( $item['rule'] ) ? $item['rule'] : '';
							$enabled    = ! empty( $item['enabled'] );
							$created_at = ! empty( $item['created_at'] ) ? $item['created_at'] : '';
							?>
							<tr>
								<td><code><?php echo esc_html( $rule ); ?></code></td>
								<td><?php echo esc_html( bbd_detect_rule_type( $rule ) ); ?></td>
								<td>
									<?php if ( $enabled ) : ?>
										<span class="bbd-badge bbd-badge-green">فعال</span>
									<?php else : ?>
										<span class="bbd-badge bbd-badge-gray">غیرفعال</span>
									<?php endif; ?>
								</td>
								<td><?php echo esc_html( $created_at ); ?></td>
								<td class="bbd-actions-cell">
									<form method="post" style="display:inline;">
										<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
										<input type="hidden" name="bbd_action" value="toggle_rule">
										<input type="hidden" name="bbd_rule" value="<?php echo esc_attr( $rule ); ?>">
										<button type="submit" class="button">
											<?php echo $enabled ? 'غیرفعال‌سازی موقت' : 'فعال‌سازی مجدد'; ?>
										</button>
									</form>

									<form method="post" style="display:inline;">
										<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
										<input type="hidden" name="bbd_action" value="delete_rule">
										<input type="hidden" name="bbd_rule" value="<?php echo esc_attr( $rule ); ?>">
										<button type="submit" class="button">حذف</button>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
					</tbody>
				</table>
			</div>

		<?php elseif ( 'blocked_activity' === $tab ) : ?>

			<div class="bbd-grid">
				<div class="bbd-panel">
					<h3>آمار دامنه‌ها و آی‌پی‌های مسدودشده</h3>
					<?php bbd_render_stat_bars( $blocked_by_host ); ?>
				</div>

				<div class="bbd-panel">
					<h3>آمار منابع درخواست در بخش مسدودشده</h3>
					<?php bbd_render_stat_bars( $blocked_by_source ); ?>
				</div>
			</div>

			<div class="bbd-panel">
				<div class="bbd-panel-header">
					<h3>لاگ ریکوئست‌های بلاک‌شده</h3>
					<form method="post">
						<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
						<input type="hidden" name="bbd_action" value="clear_blocked_logs">
						<button type="submit" class="button">پاک کردن لاگ‌ها</button>
					</form>
				</div>

				<table class="widefat striped bbd-log-table">
					<thead>
						<tr>
							<th>زمان</th>
							<th>دامنه / آی‌پی</th>
							<th>نشانی</th>
							<th>قانون منطبق</th>
							<th>منبع درخواست</th>
							<th>ناحیه</th>
							<th>متد</th>
						</tr>
					</thead>
					<tbody>
					<?php if ( empty( $blocked_logs ) ) : ?>
						<tr>
							<td colspan="7" class="bbd-empty">لاگی ثبت نشده است.</td>
						</tr>
					<?php else : ?>
						<?php foreach ( $blocked_logs as $log ) : ?>
							<tr>
								<td><?php echo esc_html( $log['time'] ?? '' ); ?></td>
								<td><?php echo esc_html( $log['host'] ?? '' ); ?></td>
								<td class="bbd-url-cell"><code><?php echo esc_html( $log['url'] ?? '' ); ?></code></td>
								<td><code><?php echo esc_html( $log['rule'] ?? '' ); ?></code></td>
								<td><?php echo esc_html( $log['source'] ?? 'نامشخص' ); ?></td>
								<td><?php echo esc_html( $log['area'] ?? '' ); ?></td>
								<td><?php echo esc_html( $log['method'] ?? '' ); ?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
					</tbody>
				</table>
			</div>

		<?php elseif ( 'slow_requests' === $tab ) : ?>

			<?php if ( ! empty( $danger_domains ) ) : ?>
				<div class="bbd-alert-panel">
					<h3>دامنه‌های پرخطر در ۲۴ ساعت اخیر</h3>
					<table class="widefat striped">
						<thead>
							<tr>
								<th>دامنه / آی‌پی</th>
								<th>تعداد</th>
								<th>میانگین</th>
								<th>بیشترین</th>
								<th>عملیات</th>
							</tr>
						</thead>
						<tbody>
						<?php foreach ( $danger_domains as $host => $row ) : ?>
							<tr>
								<td><code><?php echo esc_html( $host ); ?></code></td>
								<td><?php echo esc_html( $row['count'] ); ?></td>
								<td><?php echo esc_html( number_format_i18n( $row['avg'], 2 ) ); ?> ثانیه</td>
								<td><?php echo esc_html( number_format_i18n( $row['max'], 2 ) ); ?> ثانیه</td>
								<td>
									<form method="post" style="display:inline;">
										<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
										<input type="hidden" name="bbd_action" value="quick_block_host">
										<input type="hidden" name="bbd_host" value="<?php echo esc_attr( $host ); ?>">
										<button type="submit" class="button button-primary">افزودن به لیست مسدود</button>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			<?php endif; ?>

			<div class="bbd-grid">
				<div class="bbd-panel">
					<div class="bbd-panel-header">
						<h3>دامنه‌های کند بلاک‌نشده</h3>
						<form method="post">
							<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
							<input type="hidden" name="bbd_action" value="clear_slow_logs">
							<button type="submit" class="button">پاک کردن لاگ‌های کند</button>
						</form>
					</div>

					<table class="widefat striped">
						<thead>
							<tr>
								<th>دامنه / آی‌پی</th>
								<th>تعداد</th>
								<th>میانگین</th>
								<th>بیشترین</th>
								<th>عملیات</th>
							</tr>
						</thead>
						<tbody>
						<?php if ( empty( $unblocked_slow_stats ) ) : ?>
							<tr>
								<td colspan="5" class="bbd-empty">هنوز درخواست کندِ بلاک‌نشده‌ای ثبت نشده است.</td>
							</tr>
						<?php else : ?>
							<?php
							$counter = 0;
							foreach ( $unblocked_slow_stats as $host => $row ) :
								$counter++;
								if ( $counter > 20 ) {
									break;
								}
								?>
								<tr>
									<td><code><?php echo esc_html( $host ); ?></code></td>
									<td><?php echo esc_html( $row['count'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( $row['avg'], 2 ) ); ?> ثانیه</td>
									<td><?php echo esc_html( number_format_i18n( $row['max'], 2 ) ); ?> ثانیه</td>
									<td>
										<form method="post" style="display:inline;">
											<?php wp_nonce_field( 'bbd_admin_action', 'bbd_nonce' ); ?>
											<input type="hidden" name="bbd_action" value="quick_block_host">
											<input type="hidden" name="bbd_host" value="<?php echo esc_attr( $host ); ?>">
											<button type="submit" class="button button-primary">افزودن به لیست مسدود</button>
										</form>
									</td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
						</tbody>
					</table>
				</div>

				<div class="bbd-panel">
					<h3>آخرین درخواست‌های کند بلاک‌نشده</h3>

					<table class="widefat striped bbd-log-table">
						<thead>
							<tr>
								<th>زمان</th>
								<th>مدت</th>
								<th>دامنه / آی‌پی</th>
								<th>نشانی</th>
								<th>منبع درخواست</th>
								<th>نتیجه</th>
							</tr>
						</thead>
						<tbody>
						<?php if ( empty( $unblocked_slow_logs ) ) : ?>
							<tr>
								<td colspan="6" class="bbd-empty">لاگی ثبت نشده است.</td>
							</tr>
						<?php else : ?>
							<?php foreach ( $unblocked_slow_logs as $log ) : ?>
								<tr>
									<td><?php echo esc_html( $log['time'] ?? '' ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (float) ( $log['elapsed'] ?? 0 ), 3 ) ); ?> ثانیه</td>
									<td><?php echo esc_html( $log['host'] ?? '' ); ?></td>
									<td class="bbd-url-cell"><code><?php echo esc_html( $log['url'] ?? '' ); ?></code></td>
									<td><?php echo esc_html( $log['source'] ?? 'نامشخص' ); ?></td>
									<td><?php echo esc_html( $log['result'] ?? '' ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
						</tbody>
					</table>
				</div>
			</div>

			<div class="bbd-grid">
				<div class="bbd-panel">
					<h3>آمار دامنه‌های کند بلاک‌نشده</h3>
					<?php bbd_render_stat_bars( $unblocked_slow_bar_data ); ?>
				</div>

				<div class="bbd-panel">
					<h3>آمار منابع درخواست در کندهای بلاک‌نشده</h3>
					<?php bbd_render_stat_bars( $unblocked_slow_sources ); ?>
				</div>
			</div>

		<?php endif; ?>
	</div>

	<style>
		.bbd-wrap .nav-tab-wrapper {
			margin-bottom: 20px;
		}
		.bbd-cards {
			display: grid;
			grid-template-columns: repeat(4, minmax(180px, 1fr));
			gap: 16px;
			margin: 20px 0;
		}
		.bbd-card,
		.bbd-panel,
		.bbd-alert-panel {
			background: #fff;
			border: 1px solid #e5e7eb;
			border-radius: 12px;
			padding: 18px;
			box-shadow: 0 1px 2px rgba(16, 24, 40, .04);
			margin-bottom: 16px;
		}
		.bbd-alert-panel {
			border-color: #f59e0b;
			background: #fffaf0;
		}
		.bbd-card-title {
			color: #6b7280;
			font-size: 13px;
			margin-bottom: 8px;
		}
		.bbd-card-value {
			font-size: 28px;
			font-weight: 700;
			line-height: 1.2;
		}
		.bbd-grid {
			display: grid;
			grid-template-columns: 1fr 1fr;
			gap: 16px;
			margin: 16px 0;
		}
		.bbd-panel h3,
		.bbd-alert-panel h3 {
			margin-top: 0;
			margin-bottom: 16px;
		}
		.bbd-panel-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			gap: 10px;
			margin-bottom: 16px;
		}
		.bbd-bars {
			display: flex;
			flex-direction: column;
			gap: 12px;
		}
		.bbd-bar-row {
			display: grid;
			grid-template-columns: 220px 1fr 90px;
			gap: 10px;
			align-items: center;
		}
		.bbd-bar-label {
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
		}
		.bbd-bar-track {
			height: 10px;
			background: #eef2f7;
			border-radius: 999px;
			overflow: hidden;
		}
		.bbd-bar-fill {
			display: block;
			height: 100%;
			background: linear-gradient(90deg, #4f46e5, #7c3aed);
			border-radius: 999px;
		}
		.bbd-bar-value {
			font-weight: 600;
		}
		.bbd-add-form {
			display: flex;
			gap: 10px;
			align-items: center;
			flex-wrap: wrap;
		}
		.bbd-help-box {
			margin-top: 15px;
			padding: 12px 14px;
			background: #f8fafc;
			border: 1px solid #e2e8f0;
			border-radius: 10px;
			line-height: 2;
		}
		.bbd-empty {
			text-align: center;
			color: #6b7280;
			padding: 18px !important;
		}
		.bbd-url-cell code {
			display: inline-block;
			max-width: 520px;
			white-space: normal;
			word-break: break-all;
		}
		.bbd-actions-cell {
			display: flex;
			gap: 6px;
			flex-wrap: wrap;
		}
		.bbd-badge {
			display: inline-block;
			padding: 4px 10px;
			border-radius: 999px;
			font-size: 12px;
			font-weight: 600;
		}
		.bbd-badge-green {
			background: #ecfdf3;
			color: #027a48;
		}
		.bbd-badge-gray {
			background: #f3f4f6;
			color: #374151;
		}
		@media (max-width: 1200px) {
			.bbd-cards,
			.bbd-grid {
				grid-template-columns: 1fr;
			}
			.bbd-bar-row {
				grid-template-columns: 1fr;
			}
		}
	</style>
	<?php
}
