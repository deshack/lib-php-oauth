<?php
/**
 * PHP OAuth library.
 *
 * Based on {@link(Andy Smith, http://term.ie/)} work hosted on {@link(Google Code, http://oauth.googlecode.com/svn/code/php/)}.
 *
 * @package  OAuth
 * @author  Mattia Migliorini <migliorini.vb.italia@gmail.com>
 * @version  1.0.0
 * @since  1.0.0
 */

/**
 * Database abstraction layer interface.
 *
 * @package  OAuth
 * @version  1.0.0
 * @since  1.0.0
 */
interface OAuthDataStoreInterface {
	/**
	 * Consumer lookup.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  string $consumer_key
	 * @return OAuthConsumer
	 */
	public function lookup_consumer( $consumer_key );

	/**
	 * Token lookup.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthConsumer $consumer
	 * @param  string $token_type
	 * @param  OAuthToken $token
	 * @return bool
	 */
	public function lookup_token( $consumer, $token_type, $token );

	/**
	 * Nonce lookup.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 * @param  string $nonce
	 * @param  string $timestamp
	 * @return bool
	 */
	public function lookup_nonce( $consumer, $token, $nonce, $timestamp );

	/**
	 * Generate new request token attached to this consumer.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthConsumer $consumer
	 * @param  string $callback Optional. Default NULL.
	 * @return  OAuthToken
	 */
	public function new_request_token( $consumer, $callback = null );

	/**
	 * Generate new access token attached to this consumer.
	 *
	 * Should generate only if the request token is authorized.
	 * Should also invalidate the request token.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthToken $token
	 * @param  OAuthConsumer $consumer
	 * @param  string $verifier
	 * @return  OAuthToken
	 */
	public function new_access_token( $token, $consumer, $verifier = null );
}

/**
 * Interface of generic worker.
 *
 * @package  OAuth
 * @subpackage  Worker
 * @version  1.0.0
 * @since  1.0.0
 */
interface OAuthWorkerInterface {
	/**
	 * Process `request_token` request.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return  OAuthToken
	 */
	public function fetch_request_token( &$request );

	/**
	 * Process `access_token` request.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return  OAuthToken
	 */
	public function fetch_access_token( &$request );
}

/**
 * Interface of worker to check requests validity against a data store.
 *
 * @package OAuth
 * @subpackage  Worker
 * @version  1.0.0
 * @since  1.0.0
 */
interface OAuthServerInterface extends OAuthWorkerInterface {
	/**
	 * Constructor.
	 * Sets up the data store.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthDataStore $data_store
	 */
	public function __construct( $data_store );

	/**
	 * Set data store.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthDataStore $data_store
	 * @return  null
	 */
	public function set_data_store( $data_store );

	/**
	 * Get data store.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return OAuthDataStore
	 */
	public function get_data_store();

	/**
	 * Verify API call, check all parameters.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return  array
	 */
	public function verify_request( &$request );
}

/**
 * Interface of worker to execute a request.
 *
 * @package OAuth
 * @subpackage  Worker
 * @version  1.0.0
 * @since  1.0.0
 */
interface OAuthClientInterface extends OAuthWorkerInterface {
	/**
	 * Constructor.
	 * Sets up instance properties.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 */
	public function __construct( $consumer, $token );

	/**
	 * Get consumer.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return OAuthConsumer
	 */
	public function get_consumer();

	/**
	 * Get token.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return OAuthToken
	 */
	public function get_token();
}

/**
 * Generic exception class.
 *
 * @package OAuth
 * @subpackage Exception
 * @version 1.0.0
 * @since  1.0.0
 */
class OAuthException extends Exception {

}

/**
 * Data type that represents the identity of the Consumer
 * via its shared secred with the Service Provider.
 *
 * @package  OAuth
 * @version 1.0.0
 * @since  1.0.0
 */
class OAuthConsumer {
	/**
	 * Consumer Key.
	 *
	 * @since  1.0.0
	 * @access public
	 * @var string
	 */
	public $key;


	/**
	 * Shared Secret.
	 *
	 * @since  1.0.0
	 * @access public
	 * @var string
	 */
	public $secret;

	/**
	 * Constructor.
	 * Sets up instance properties.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  string $key
	 * @param  string $secret
	 * @param  string $callback_url Optional. Default NULL.
	 */
	public function __construct( $key, $secret, $callback_url = NULL ) {
		$this->key = $key;
		$this->secret = $secret;
		$this->callback_url = $callback_url;
	}

	/**
	 * Magic method to convert OAuthConsumer object to string.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @return  string
	 */
	public static function __toString() {
		return "OAuthConsumer[key=$this->key,secret=$this->secret]";
	}
}

/**
 * Data type that represents an End User via either an access
 * or request token.
 *
 * @package  OAuth
 * @version  1.0.0
 * @since  1.0.0
 */
class OAuthToken {
	/**
	 * Access and request tokens.
	 *
	 * @since  1.0.0
	 * @access public
	 * @var string
	 */
	public $key;

	/**
	 * Shared secret.
	 *
	 * @since  1.0.0
	 * @access public
	 * @var string
	 */
	public $secret;

	/**
	 * Constructor.
	 * Sets up instance properties.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  string $key Token.
	 * @param  string $secret Token secret.
	 */
	public function __construct( $key, $secret ) {
		$this->key = $key;
		$this->secret = $secret;
	}

	/**
	 * Generate basic string serialization of a token that a server
	 * would respond to request_token and access_token calls with.
	 *
	 * @since  1.0.0
	 * @access private
	 *
	 * @return  string
	 */
	private function to_string() {
		return "oauth_token=" . 
			OAuthUtil::urlencode_rfc3986( $this->key ) .
			"&oauth_token_secret=" .
			OAuthUtil::urlencode_rfc3986( $this->secret );
	}

	/**
	 * Magic method to convert object to string.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return  string
	 */
	public function __toString() {
		return $this->to_string();
	}
}

/**
 * Strategy class to implement Signature Method.
 *
 * @package  OAuth
 * @subpackage SignatureMethod
 * @version  1.0.0
 * @since  1.0.0
 * @abstract
 */
abstract class OAuthSignatureMethod {
	/**
	 * Get name of the Signature Method (ie. HMAC-SHA1).
	 *
	 * @since  1.0.0
	 * @access public
	 * @abstract
	 *
	 * @return  string
	 */
	abstract public function get_name();

	/**
	 * Build up the signature.
	 *
	 * NOTE: The output of this function MUST NOT be urlencoded.
	 * The encoding is handled in OAuthRequest when the final request is serialized.
	 *
	 * @since  1.0.0
	 * @access public
	 * @abstract
	 *
	 * @param  OAuthRequest $request
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 * @return string
	 */
	abstract public function build_signature( $request, $consumer, $token );

	/**
	 * Verify signature.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthRequest $request
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 * @param  string $signature
	 * @return bool
	 */
	public function check_signature( $request, $consumer, $token, $signature ) {
		$built = $this->build_signature( $request, $consumer, $token );

		// Check for zero length, although unlikely here.
		if ( strlen( $built ) == 0 || strlen( $signature ) == 0 )
			return false;

		if ( strlen( $built ) != strlen( $signature ) )
			return false;

		// Avoid timing leak with a (hopefully) time insensitive compare.
		$result = 0;
		for ( $i = 0; $i < strlen( $signature ); $i++ )
			$result |= ord( $built{$i} ) ^ ord( $signature{$i} );
		return $result == 0;
	}
}

/**
 * The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in
 * [RFC2104] where the Signature Base String is the text and the key is the concatenated
 * values (each first encoded per Parameter Encoding) of the Consumer Secret and Token Secret,
 * separated be an '&' character (ASCII code 38) even if empty.
 *
 * @package OAuth
 * @subpackage  SignatureMethod
 * @version  1.0.0
 * @since  1.0.0
 */
class OAuthSignatureMethod_HMAC_SHA1 extends OAuthSignatureMethod {
	function get_name() {
		return "HMAC-SHA1";
	}

	public function build_signature( $request, $consumer, $token ) {
		$base_string = $request->get_signature_base_string();
		$request->base_string = $base_string;

		$key_parts = array(
			$consumer->secret,
			($token) ? $token->secret : ''
		);

		$key_parts = OAuthUtil::urlencode_rfc3986( $key_parts );
		$key = implode( '&', $key_parts );

		return base64_encode( hash_hmac( 'sha1', $base_string, $key, true ) );
	}
}

/**
 * The PLAINTEXT Method does not provide any security protection and SHOULD only be used
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *
 * @package  OAuth
 * @subpackage  SignatureMethod
 * @version  1.0.0
 * @since  1.0.0
 */
class OAuthSignatureMethod_PLAINTEXT extends OAuthSignatureMethod {
	public function get_name() {
		return 'PLAINTEXT';
	}

	/**
	 * `oauth_signature` is set to the concatenated encoded values of the Consumer Secret and
	 * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is
	 * emty. The result MUST be encoded again.
	 *
	 * Please note that the second encoding MUST NOT happen in the Signature Method, as
	 * OAuthRequest handles this.
	 */
	public function build_signature( $request, $consumer, $token ) {
		$key_parts = array(
			$consumer->secret,
			($token) ? $token->secret : ''
		);

		$key_parts = OAuthUtil::urlencode_rfc3986( $key_parts );
		$key = implode( '&', $key_parts );
		$request->base_string = $key;
		return $key;
	}
}

/**
 * The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature algorithm as defined in
 * [RFC3447] section 8.2 (more simply known as PKCS#1), using SHA-1 as the hash function for
 * EMSA-PKCS1-v1_5. It is assumed that the Consumer also provided its RSA public key in a
 * verified way to the Service Provider, in a manner which is beyond the scope of this specification.
 *
 * @package  OAuth
 * @subpackage  SignatureMethod
 * @version  1.0.0
 * @since  1.0.0
 * @abstract
 */
abstract class OAuthSignatureMethod_RSA_SHA1 extends OAuthSignatureMethod {
	public function get_name() {
		return 'RSA-SHA1';
	}

	/**
	 * Fetch public certificate.
	 * 
	 * Up to the Service Provider to implement this lookup of keys.
	 * Possible ideas are:
	 * (1) do a lookup in a table of trusted certs keyed off of consumer
	 * (2) fetch via http using a URL provided by the requester
	 * (3) some sort of specific discovery code based on request.
	 *
	 * Either way should return a string representation of the certificate.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @abstract
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return string
	 */
	protected abstract function fetch_public_cert( &$request );

	/**
	 * Fetch private certificate.
	 * 
	 * Up to the Service Provider to implement this lookup of keys.
	 * Possible ideas are:
	 * (1) do a lookup in a table of trusted certs keyed off of consumer.
	 *
	 * Either way should return a string representation of the certificate.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @abstract
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return string
	 */
	protected abstract function fetch_private_cert( &$request );

	public function build_signature( $request, $consumer, $token ) {
		$base_string = $request->get_signature_base_string();
		$request->base_string = $base_string;

		// Fetch private key cert based on the request.
		$cert = $this->fetch_private_cert( $request );

		// Pull the private key ID from the certificate.
		$privatekeyid = openssl_get_privatekey( $cert );

		// Sign using the key.
		$ok = openssl_sign( $base_string, $signature, $privatekeyid );

		// Release the key resource.
		openssl_free_key( $privatekeyid );

		return base64_encode( $signature );
	}

	public function check_signature( $request, $consumer, $token, $signature ) {
		$decoded_sig = base64_decode( $signature );

		$base_string = $request->get_signature_base_string();

		// Fetch the public key cert based on the request.
		$cert = $this->fetch_public_cert( $request );

		// Pull the public key ID from the certificate.
		$publickeyid = openssl_get_publickey( $cert );

		// Check the computed signature against the one passed in the query.
		$ok = openssl_verify( $base_string, $decoded_sig, $publickeyid );

		// Release the key resource.
		openssl_free_key( $publickeyid );

		return $ok == 1;
	}
}

/**
 * Request data type.
 * Can be serialized.
 *
 * @package  OAuth
 * @version  1.0.0
 * @since  1.0.0
 */
class OAuthRequest {
	/**
	 * Request parameters.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @var array
	 */
	protected $parameters;

	/**
	 * Request HTTP method.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @var string
	 */
	protected $http_method;

	/**
	 * Request HTTP URL.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @var string
	 */
	protected $http_url;

	/**
	 * Base string, for debug purposes.
	 *
	 * @since  1.0.0
	 * @access public
	 * @var string
	 */
	public $base_string;

	/**
	 * HTTP version.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 * @var string
	 */
	public static $version = '1.0';

	/**
	 * POST input.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 */
	public static $POST_INPUT = 'php://input';

	/**
	 * Constructor.
	 *
	 * Sets up object properties.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  string $http_method
	 * @param  string $http_url
	 * @param  array $parameters Optional. Default NULL.
	 */
	public function __construct( $http_method, $http_url, $parameters = NULL ) {
		$parameters = ($parameters) ? $parameters : array();
		$parameters = array_merge( OAuthUtil::parse_parameters( parse_url( $http_url, PHP_URL_QUERY ) ), $parameters );
		$this->parameters = $parameters;
		$this->http_method = $http_method;
		$this->http_url = $http_url;
	}

	/**
	 * Attempt to build up a request from what was passed to the server.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @param  string $http_method Optional. Default NULL.
	 * @param  string $http_url Optional. Default NULL.
	 * @param  array $parameters Optional. Default NULL.
	 * @return OAuthRequest
	 */
	public static function from_request( $http_method = NULL, $http_url = NULL, $parameters = NULL ) {
		$scheme = (!isset( $_SERVER['HTTPS'] ) || $_SERVER['HTTPS'] != 'on' ) ? 'http' : 'https';
		$http_url = ($http_url) ? $http_url : $scheme . '://' . $_SERVER['SERVER_NAME'] . ':' . $_SERVER['SERVER_PORT'] . $_SERVER['REQUEST_URI'];
		$http_method = ($http_method) ? $http_method : $_SERVER['REQUEST_METHOD'];

		// We weren't handed any parameters, so let's find the ones relevant to this request.
		// If you run XML-RPC or similar you should use this to provide your own parsed parameter-list.
		if ( !$parameters ) {
			// Find request headers.
			$request_headers = OAuthUtil::get_headers();

			// Parse the query-string to find GET parameters.
			$parameters = OAuthUtil::parse_parameters( $_SERVER['QUERY_STRING'] );

			// It's a POST request of the proper content-type, so parse POST parameters and add those
			// overriding any duplicates of GET.
			if ( $http_method == 'POST' && isset( $request_headers['Content-Type'] ) && strstr( $request_headers['Content-Type'], 'application/x-www-form-urlencoded' ) ) {
				$post_data = OAuthUtil::parse_parameters( file_get_contents( self::$POST_INPUT ) );
				$parameters = array_merge( $parameters, $post_data );
			}

			// We have an Authorization-header with OAuth data. Parse the header and add those overriding
			// any duplicates from GET or POST.
			if ( isset( $request_headers['Authorization'] ) && substr( $request_headers['Authorization'], 0, 6 ) == 'OAuth ' ) {
				$header_parameters = OAuthUtil::split_header( $request_headers['Authorization'] );
				$parameters = array_merge( $parameters, $header_parameters );
			}
		}

		return new OAuthRequest( $http_method, $http_url, $parameters );
	}

	/**
	 * Helper function to set up the request.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 * @param  string $http_method
	 * @param  string $http_url
	 * @param  array $parameters Optional. Default NULL.
	 * @return OAuthRequest
	 */
	public static function from_consumer_and_token( $consumer, $token, $http_method, $http_url, $parameters = NULL ) {
		$parameters = ($parameters) ? $parameters : array();
		$defaults = array( 'oauth_version' => OAuthRequest::$version,
			'oauth_nonce' => OAuthRequest::generate_nonce(),
			'oauth_timestamp' => OAuthRequest::generate_timestamp(),
			'oauth_consumer_key' => $consumer->key
		);

		if ( $token )
			$defaults['oauth_token'] = $token->key;

		$parameters = array_merge( $defaults, $parameters );

		return new OAuthRequest( $http_method, $http_url, $parameters );
	}

	/**
	 * Set parameter.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  string $name
	 * @param  string $value
	 * @param  bool $allow_duplicates Optional. Default true.
	 */
	public function set_parameter( $name, $value, $allow_duplicates = true ) {
		if ( $allow_duplicates && isset( $this->parameters[$name] ) ) {
			// We already added parameter(s) with this name, so add to the list.
			if ( is_scalar( $this->parameters[$name] ) )
				// This is the first duplicate, so transform scalar (string) into an array
				// so we can add the duplicates.
				$this->parameters[$name] = array( $this->parameters[$name] );

			$this->parameters[$name][] = $value;
		} else {
			$this->parameters[$name] = $value;
		}
	}

	/**
	 * Retrieve parameter value.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  string $name
	 * @return string
	 */
	public function get_parameter( $name ) {
		return isset( $this->parameters[$name] ) ? $this->parameters[$name] : null;
	}

	/**
	 * Retrieve all parameters.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return  array
	 */
	public function get_parameters() {
		return $this->parameters;
	}

	/**
	 * Remove parameter.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  string $name
	 */
	public function unset_parameter( $name ) {
		unset( $this->parameters[$name] );
	}

	/**
	 * The request parameters, sorted and concatenated into a normalized string.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return  string
	 */
	public function get_signable_parameters() {
		// Grab all parameters.
		$params = $this->parameters;

		// Remove oauth_signature if present.
		// Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.").
		if ( isset( $params['oauth_signature'] ) )
			unset( $params['oauth_signature'] );

		return OAuthUtil::build_http_query( $params );
	}

	/**
	 * Get base string of this request.
	 *
	 * The base string defined as the method, the url and the parameters (normalized),
	 * each urlencoded and concatenated with &.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return  string
	 */
	public function get_signature_base_string() {
		$parts = array(
			$this->get_normalized_http_method(),
			$this->get_normalized_http_url(),
			$this->get_signable_parameters()
		);

		$parts = OAuthUtil::urlencode_rfc3986( $parts );

		return implode( '&', $parts );
	}

	/**
	 * Uppercase the HTTP method.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return string
	 */
	public function get_normalized_http_method() {
		return strtoupper( $this->http_method );
	}

	/**
	 * Parse the URL and rebuild it to be `scheme://host/path`.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return  string
	 */
	public function get_normalized_http_url() {
		$parts = parse_url( $this->http_url );

		$scheme = (isset( $parts['scheme'] )) ? $parts['scheme'] : 'http';
		$port = (isset( $parts['port'] )) ? $parts['port'] : (($scheme == 'https') ? '443' : '80');
		$host = (isset( $parts['host'] )) ? $parts['host'] : '';
		$path = (isset( $parts['path'] )) ? $parts['path'] : '';

		if ( ( $scheme == 'https' && $port != '443' ) || ( $scheme == 'http' && $port != '80' ) )
			$host = "$host:$port";

		return "$scheme://$host$path";
	}

	/**
	 * Build URL usable for a GET request.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return  string
	 */
	public function to_url() {
		$post_data = $this->to_postdata();
		$out = $this->get_normalized_http_url();
		if ( $post_data )
			$out .= '?' . $post_data;
		return $out;
	}

	/**
	 * Build data for POST request.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return  string
	 */
	public function to_postdata() {
		return OAuthUtil::build_http_query( $this->parameters );
	}

	/**
	 * Build Autorization header.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  string $realm
	 * @return  string
	 */
	public function to_header( $realm = null ) {
		$first = true;

		if ( $realm ) {
			$out = 'Authorization: OAuth realm="' . OAuthUtil::urlencode_rfc3986( $realm ) . '"';
			$first = false;
		} else {
			$out = 'Authorization: OAuth';
		}

		$total = array();
		foreach ( $this->parameters as $k => $v ) {
			if ( substr( $k, 0, 5 ) != 'oauth' )
				continue;
			if ( is_array( $v ) )
				throw new OAuthException('Arrays not supported in headers');
			$out .= ($first) ? ' ' : ',';
			$out .= OAuthUtil::urlencode_rfc3986( $k ) . '="' . OAuthUtil::urlencode_rfc3986( $v ) . '"';
			$first = false;
		}

		return $out;
	}

	/**
	 * Magic method to convert object to string.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @return  string
	 */
	public function __toString() {
		return $this->to_url();
	}

	/**
	 * Set signature for current request.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthSignatureMethod $signature_method
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 * @return  null
	 */
	public function sign_request( $signature_method, $consumer, $token ) {
		$this->set_parameter( 'oauth_signature_method', $signature_method->get_name(), false );
		$signature = $this->build_signature( $signature_method, $consumer, $token );
		$this->set_parameter( 'oauth_signature', $signature, false );
	}

	/**
	 * Build signature.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthSignatureMethod $signature_method
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 * @return  string
	 */
	public function build_signature( $signature_method, $consumer, $token ) {
		$signature = $signature_method->build_signature( $this, $consumer, $token );
		return $signature;
	}

	/**
	 * Helper function to generate timestamp.
	 *
	 * @since  1.0.0
	 * @access private
	 * @static
	 *
	 * @return  string
	 */
	private static function generate_timestamp() {
		return time();
	}

	/**
	 * Helper function to generate nonce.
	 *
	 * @since  1.0.0
	 * @access private
	 * @static
	 *
	 * @return  string
	 */
	private static function generate_nonce() {
		$mt = microtime();
		$rand = mt_rand();

		return md5( $mt . $rand ); // md5 look nicer than numbers.
	}
}

/**
 * Worker to check requests validity against a data store.
 *
 * @package OAuth
 * @version  1.0.0
 * @since  1.0.0
 */
class OAuthServer implements OAuthServerInterface {
	/**
	 * Time limit in seconds.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @var int
	 */
	protected $timestamp_threshold = 300; // 5 minutes

	/**
	 * OAuth Version.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @var string
	 */
	protected $version = '1.0';

	/**
	 * Accepted signature methods.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @var array
	 */
	protected $signature_methods = array();

	/**
	 * Data store.
	 *
	 * @since  1.0.0
	 * @access protected
	 * @var OAuthDataStore
	 */
	protected $data_store;

	/**
	 * Constructor.
	 * Sets up the data store.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthDataStore $data_store
	 */
	public function __construct( $data_store ) {
		$this->data_store = $data_store;
	}

	/**
	 * Add signature method.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthSignatureMethod $signature_method
	 */
	public function add_signature_method( $signature_method ) {
		$this->signature_methods[$signature_method->get_name()] = $signature_method;
	}

	/**
	 * Process `request_token` request.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return  OAuthToken
	 */
	public function fetch_request_token( &$request ) {
		$this->get_version( $request );

		$consumer = $this->get_consumer( $request );

		// No token required for the initial token request.
		$token = null;

		$this->check_signature( $request, $consumer, $token );

		$callback = $request->get_parameter( 'oauth_callback' );
		$new_token = $this->data_store->new_request_token( $consumer, $callback );

		return $new_token;
	}

	/**
	 * Process `access_token` request.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return  OAuthToken
	 */
	public function fetch_access_token( &$request ) {
		$this->get_version( $request );

		$consumer = $this->get_consumer( $request );

		// Requires authorized request token.
		$token = $this->get_token( $request, $consumer, 'request' );

		$this->check_signature( $request, $consumer, $token );

		$verifier = $request->get_parameter( 'oauth_verifier' );
		$new_token = $this->data_store->new_access_token( $token, $consumer, $verifier );

		return $new_token;
	}

	/**
	 * Verify API call, check all parameters.
	 *
	 * @since  1.0.0
	 * @access public
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return  array
	 */
	public function verify_request( &$request ) {
		$this->get_version( $request );
		$consumer = $this->get_consumer( $request );
		$token = $this->get_token( $request, $consumer, 'access' );
		$this->check_signature( $request, $consumer, $token );
		return array( $consumer, $token );
	}

	//--------------------------------------------------
	// INTERNALS
	//--------------------------------------------------
	
	/**
	 * Get request OAuth version.
	 *
	 * @since  1.0.0
	 * @access private
	 *
	 * @param  OAuthRequest $request Passed by reference.
	 * @return  string
	 */
	public function get_version( &$request ) {
		$version = $request->get_parameter( 'oauth_version' );

		if ( ! $version )
			// Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
			// Chapter 7.0 ("Accessing Protected Resources").
			$version = '1.0';
		if ( $version !== $this->version )
			throw new OAuthException( "OAuth version '$version' not supported" );

		return $version;
	}

	/**
	 * Figure out the signature with some defaults.
	 *
	 * @since  1.0.0
	 * @access private
	 *
	 * @param  OAuthRequest $request
	 * @return OAuthSignatureMethod
	 */
	private function get_signature_method( $request ) {
		$signature_method = $request instanceof OAuthRequest ? $request->get_parameter( 'oauth_signature_method' ) : null;

		if ( ! $signature_method )
			// According to chapter 7 ("Accessing Protected Resources") the signature_method parameter is required,
			// and we can't just fallback to PLAINTEXT.
			throw new OAuthException( 'No signature method parameter. This parameter is required.' );

		if ( ! in_array( $signature_method, array_keys( $this->signature_methods ) ) )
			throw new OAuthException("Signature method '$signature_method' not supported. Try one of the following: " . implode( ', ', array_keys( $this->signature_methods ) ) );
		return $this->signature_methods[$signature_method];
	}

	/**
	 * Try to find the consumer for the provided request's consumer key.
	 *
	 * @since  1.0.0
	 * @access private
	 *
	 * @param  OAuthRequest $request
	 * @return  OAuthConsumer
	 */
	private function get_consumer( $request ) {
		$consumer_key = $request instanceof OAuthRequest ? $request->get_parameter( 'oauth_consumer_key' ) : null;

		if ( ! $consumer_key )
			throw new OAuthException( 'Invalid consumer key.' );

		$consumer = $this->data_store->lookup_consumer( $consumer_key );

		if ( ! $consumer )
			throw new OAuthException( 'Invalid consumer' );

		return $consumer;
	}

	/**
	 * Try to find the token for the provided request's token key.
	 *
	 * @since  1.0.0
	 * @access private
	 *
	 * @param  OAuthRequest $request
	 * @param  OAuthConsumer $consumer
	 * @param  string $token_type
	 * @return  OAuthToken
	 */
	private function get_token( $request, $consumer, $token_type = 'access' ) {
		$token_field = $request instanceof OAuthRequest ? $request->get_parameter( 'oauth_token' ) : null;

		$token = $this->data_store->lookup_token( $consumer, $token_type, $token_field );
		if ( ! $token )
			throw new OAuthException( "Invalid $token_type token: $token_field" );
		return $token;
	}

	/**
	 * Check signature on a request.
	 *
	 * Should guess the signature method appropriately.
	 *
	 * @since  1.0.0
	 * @access private
	 *
	 * @param  OAuthRequest $request
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 */
	private function check_signature( $request, $consumer, $token ) {
		// TODO: This should probably be in a different method.
		$timestamp = $request instanceof OAuthRequest ? $request->get_parameter( 'oauth_timestamp' ) : null;
		$nonce = $request instanceof OAuthRequest ? $request->get_parameter( 'oauth_nonce' ) : null;

		$this->check_timestamp( $timestamp );
		$this->check_nonce( $consumer, $token, $nonce, $timestamp );

		$signature_method = $this->get_signature_method( $request );

		$signature = $request->get_parameter( 'oauth_signature' );
		$valid_sig = $signature_method->check_signature( $request, $consumer, $token, $signature );

		if ( ! $valid_sig )
			throw new OAuthException('Invalid signature');
	}

	/**
	 * Check that the timestamp is new enough.
	 *
	 * @since  1.0.0
	 * @access private
	 *
	 * @param  string $timestamp
	 */
	private function check_timestamp( $timestamp ) {
		if ( ! $timestamp )
			throw new OAuthException('Missing timestamp parameter. The parameter is required.');

		// Verify that timestamp is recentish.
		$now = time();
		if ( abs( $now - $timestamp ) > $this->timestamp_threshold )
			throw new OAuthException( "Expired timestamp, yours $timestamp, outs $now" );
	}

	/**
	 * Check nonce uniqueness.
	 *
	 * @since  1.0.0
	 * @access private
	 *
	 * @param  OAuthConsumer $consumer
	 * @param  OAuthToken $token
	 * @param  string $nonce
	 * @param  string $timestamp
	 */
	private function check_nonce( $consumer, $token, $nonce, $timestamp ) {
		if ( ! $nonce )
			throw new OAuthException('Missing nonce parameter. The parameter is required.');

		// Verify that the nonce is unique.
		$found = $this->data_store->lookup_nonce( $consumer, $token, $nonce, $timestamp );
		if ( $found )
			throw new OAuthException("Nonce already used: $nonce");
	}
}

/**
 * Utility class.
 *
 * @package  OAuth
 * @version  1.0.0
 * @since  1.0.0
 */
class OAuthUtil {
	/**
	 * Encode URL according to RFC3986 specs.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @param  midex $input
	 * @return  string
	 */
	public static function urlencode_rfc3986( $input ) {
		if ( is_array( $input ) ) {
			return array_map( array( 'OAuthUtil', 'urlencode_rfc3986' ), $input );
		} elseif ( is_scalar( $input ) ) {
			return str_replace(
				'+',
				' ',
				str_replace( '%7E', '~', rawurlencode( $input ) )
			);
		} else {
			return '';
		}
	}

	/**
	 * Decode URL encoded according to RFC3986 specs.
	 *
	 * @todo This decode function doesn't take into consideration the above modifications
	 * to the encoding process.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @param  string $string
	 * @return  string
	 */
	public static function urldecode_rfc3986( $string ) {
		return urldecode( $string );
	}

	/**
	 * Helper function for turning the Authorization header into parameters.
	 *
	 * Has to do some unescaping.
	 * Can filter out any non-oauth parameters if needed (default behaviour).
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @param  string $header
	 * @param  bool $only_allow_oauth Optional. Default true.
	 * @return  array
	 */
	public static function split_header( $header, $only_allow_oauth = true ) {
		$params = array();
		if ( preg_match_all( '/(' . ($only_allow_oauth ? 'oauth_' : '') . '[a-z_-]*)=(:?"([^"]*)"|([^,]*))/', $header, $matches ) ) {
			foreach ( $matches[1] as $i => $h )
				$params[$h] = OAuthUtil::urldecode_rfc3986( empty( $matches[3][$i] ) ? $matches[4][$i] : $matches[3][$i] );
			if ( isset( $params['realm'] ) )
				unset( $params['realm'] );
		}

		return $params;
	}

	/**
	 * Helper function to sort out headers for people who aren't running apache.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @return  array
	 */
	public static function get_headers() {
		if ( function_exists( 'apache_request_headers' ) ) {
			// We need this to get the actual Authorization header because apache tends
			// to tell us it doesn't exist.
			$headers = apache_request_headers();

			// Sanitize the output of apache_request_headers because we always want the
			// keys to be Cased-Like-This and arh() returns the headers in the same case
			// as they are in the request.
			$out = array();
			foreach ( $headers as $k => $v ) {
				$k = str_replace(
					' ',
					'-',
					ucwords( strtolower( str_replace( '-', ' ', $k ) ) )
				);
				$out[$k] = $v;
			}
		} else {
			// Otherwise we don't have apache and are just going to have to hope that
			// $_SERVER actually contains what we need.
			$out = array();
			if ( isset( $_SERVER['CONTENT_TYPE'] ) )
				$out['Content-Type'] = $_SERVER['CONTENT_TYPE'];
			if ( isset( $_ENV['CONTENT_TYPE'] ) )
				$out['Content-Type'] = $_ENV['CONTENT_TYPE'];

			foreach ( $_SERVER as $k => $v ) {
				if ( substr( $k, 0, 5 ) == 'HTTP_' ) {
					// This is chaos, basically it is just there to capitalize the first
					// letter of every word that is not an initial HTTP and strip HTTP
					$k = str_replace(
						' ',
						'-',
						ucwords( strtolower( str_replace( '_', ' ', substr( $k, 5 ) ) ) )
					);
					$out[$k] = $v;
				}
			}
		}

		return $out;
	}

	/**
	 * Turn URL parameters into array.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @param  string $input
	 * @return array
	 */
	public static function parse_parameters( $input ) {
		if ( ! isset( $input ) || ! $input )
			return array();

		$pairs = explode( '&', $input );

		$parsed_params = array();
		foreach ( $pairs as $pair ) {
			$split = explode( '=', $pair, 2 );
			$parameter = OAuthUtil::urldecode_rfc3986( $split[0] );
			$value = isset( $split[1] ) ? OAuthUtil::urldecode_rfc3986( $split[1] );

			if ( isset( $parsed_params[$parameter] ) ) {
				// We already received parameter(s) with this name, so add to the list
				// of parameters with this name.
				if ( is_scalar( $parsed_params[$parameter] ) )
					// This is the first duplicate, so transform scalar (string) into array
					// so we can add duplicates.
					$parsed_params[$parameter] = array( $parsed_params[$parameter] );

				$parsed_params[$parameter][] = $value;
			} else {
				$parsed_params[$parameter] = $value;
			}
		}

		return $parsed_params;
	}

	/**
	 * Build HTTP query.
	 *
	 * Turns a list of parameters (array) into string.
	 *
	 * @since  1.0.0
	 * @access public
	 * @static
	 *
	 * @param  array $params
	 * @return string
	 */
	public static function build_http_query( $params ) {
		if ( ! $params )
			return '';

		// Urlencode both keys and values.
		$keys = OAuthUtil::urlencode_rfc3986( array_keys( $params ) );
		$values = OAuthUtil::urlencode_rfc3986( array_values( $params ) );
		$params = array_combine( $keys, $values );

		// Parameters are sorted by name, using lexicographical byte value ordering.
		// Ref: Spec: 9.1.1 (1)
		uksort( $params, 'strcmp' );

		$pairs = array();
		foreach ( $params as $p => $v ) {
			if ( is_array( $v ) ) {
				// If two or more parameters share the same name, they are sorted by their value.
				// Ref: Spec: 9.1.1 (1).
				sort( $v, SORT_STRING );
				foreach ( $v as $duplicate_v )
					$pairs[] = $p . '=' . $duplicate_v;
			} else {
				$pairs[] = $p . '=' . $v;
			}
		}

		// For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61).
		// Each name-value pair is separated by an '&' character (ASCII code 38).
		return implode( '&', $pairs );
	}
}