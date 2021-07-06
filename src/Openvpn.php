<?php

namespace Paranic;

class Openvpn {

	public $server_address = '127.0.0.1';
	public $server_port = '1194';
	public $protocol = 'udp';
	public $easy_rsa_folder = '/tmp/easy-rsa';
	public $network = '10.0.0.0';
	public $netmask = '255.255.255.0';

	function __construct()
	{
		if ($this->isEasyRSASetup()) {
			$this->easy_rsa_folder = realpath(__DIR__ . '/easy-rsa');
		} else {
			$this->easy_rsa_folder = __DIR__ . '/easy-rsa';
		}
	}

	public function setup()
	{
		// Check if debian version is 10.x (buster)
		if (is_file('/etc/debian_version') AND $ver = file_get_contents('/etc/debian_version')) {
			if (intval(trim($ver)) !== 10) {
				die('Invalid operating system or version. This library runs on debian 10.' . PHP_EOL);
			}
		} else {
			die('Invalid operating system. This library runs on debian.' . PHP_EOL);
		}

		// Check if we have openvpn package installed
		if (strlen(exec('dpkg -l openvpn')) == 0) {
			die('openvpn package is not installed.' . PHP_EOL);
		}

		// Check if we have easy-rsa package installed
		if (strlen(exec('dpkg -l easy-rsa')) == 0) {
			die('easy-rsa package is not installed.' . PHP_EOL);
		}

		// Check if folder is available
		if ($this->isEasyRSASetup()) {
			die('Cannot setup to ' . $this->easy_rsa_folder . ', an item already exists.' . PHP_EOL);
		}

		// Create easy-rsa and required directories
		shell_exec('make-cadir ' . $this->easy_rsa_folder);
		$this->easy_rsa_folder = realpath($this->easy_rsa_folder);

		// Create generated required folders
		shell_exec('mkdir -p ' . $this->easy_rsa_folder . '/configs');
		shell_exec('mkdir -p ' . $this->easy_rsa_folder . '/ccd');

		// Create variables file
		$vars = $this->varsFileContents();
		file_put_contents($this->easy_rsa_folder . '/vars', $vars);

		shell_exec('cd ' . $this->easy_rsa_folder . ' && ./easyrsa init-pki');
		shell_exec('cd ' . $this->easy_rsa_folder . ' && ./easyrsa build-ca nopass');
		shell_exec('cd ' . $this->easy_rsa_folder . ' && openvpn --genkey --secret tls-crypt.key');

		return true;
	}

	public function create_server()
	{
		if (!$this->isEasyRSASetup()) die('Please invoke setup() first.' . PHP_EOL);

		// Check if we already created server
		if (in_array('server.conf', $this->existing_keys())) die('Server already created.' . PHP_EOL);

		shell_exec('cd ' . $this->easy_rsa_folder . ' && ./easyrsa gen-req servername nopass');
		shell_exec('cd ' . $this->easy_rsa_folder . ' && ./easyrsa sign-req server servername');

		$ca = trim(file_get_contents($this->easy_rsa_folder . '/pki/ca.crt'));

		$cert = trim(file_get_contents($this->easy_rsa_folder . '/pki/issued/servername.crt'));
		preg_match('/(-----BEGIN CERTIFICATE-----)(?s)(.*?)(-----END CERTIFICATE-----)/', $cert, $match);
		$cert = $match[0];

		$key = trim(file_get_contents($this->easy_rsa_folder . '/pki/private/servername.key'));

		$tls_crypt = trim(file_get_contents($this->easy_rsa_folder . '/tls-crypt.key'));
		preg_match('/(-----BEGIN OpenVPN Static key V1-----)(?s)(.*?)(-----END OpenVPN Static key V1-----)/', $tls_crypt, $match);
		$tls_crypt = $match[0];

		$server_conf = $this->generate_server_conf($ca, $cert, $key, $tls_crypt);

		file_put_contents($this->easy_rsa_folder . '/configs/server.conf', $server_conf);

		return true;
	}

	public function create_client($client_name = NULL, $last_octet = 1)
	{
		if (!$this->isEasyRSASetup()) die('Please invoke setup() first.' . PHP_EOL);

		// Check client_name
		if (is_null($client_name) OR empty($client_name)) die('Please input client name that you want to create.' . PHP_EOL);

		// Check if client_name exists in our keys database
		if (in_array($client_name . '.conf', $this->existing_keys())) die('Client name already exists in database.' . PHP_EOL);

		shell_exec('cd ' . $this->easy_rsa_folder . ' && export EASYRSA_REQ_CN="' . $client_name . '" ; ./easyrsa gen-req ' . $client_name . ' nopass');
		shell_exec('cd ' . $this->easy_rsa_folder . ' && export EASYRSA_REQ_CN="' . $client_name . '" ; ./easyrsa sign-req client ' . $client_name);

		$ca = trim(file_get_contents($this->easy_rsa_folder . '/pki/ca.crt'));

		$cert = trim(file_get_contents($this->easy_rsa_folder . '/pki/issued/' . $client_name . '.crt'));
		preg_match('/(-----BEGIN CERTIFICATE-----)(?s)(.*?)(-----END CERTIFICATE-----)/', $cert, $match);
		$cert = $match[0];

		$key = trim(file_get_contents($this->easy_rsa_folder . '/pki/private/' . $client_name . '.key'));

		$tls_crypt = trim(file_get_contents($this->easy_rsa_folder . '/tls-crypt.key'));
		preg_match('/(-----BEGIN OpenVPN Static key V1-----)(?s)(.*?)(-----END OpenVPN Static key V1-----)/', $tls_crypt, $match);
		$tls_crypt = $match[0];

		$client_conf = $this->generate_client_conf($ca, $cert, $key, $tls_crypt);

		file_put_contents($this->easy_rsa_folder . '/configs/' . $client_name . '.conf', $client_conf);

		$long = ip2long($this->network) + $last_octet;
		$node_ip_address = long2ip($long);

		file_put_contents($this->easy_rsa_folder . '/ccd/' . $client_name, 'ifconfig-push ' . $node_ip_address . ' ' . $this->netmask);

		return true;
	}

	public function existing_keys()
	{
		$existing_keys = [];
		foreach (new \DirectoryIterator($this->easy_rsa_folder . '/configs/') as $file_info) {
			if ($file_info->isDot() OR !$file_info->isFile()) continue;

			array_push($existing_keys, $file_info->getBasename());
		}

		return $existing_keys;
	}

	private function isEasyRSASetup()
	{
		return file_exists($this->easy_rsa_folder);
	}

	private function varsFileContents()
	{
		return <<<EOT
set_var EASYRSA_ALGO ec
set_var EASYRSA_CURVE secp521r1
set_var EASYRSA_DIGEST "sha512"
set_var EASYRSA_BATCH "true"
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 3650
EOT;
	}

	private function generate_server_conf($ca, $cert, $key, $tls_crypt)
	{
		return <<<EOT
proto $this->protocol
port $this->server_port
dev tun
verb 5
<ca>
$ca
</ca>
<cert>
$cert
</cert>
<key>
$key
</key>
<tls-crypt>
$tls_crypt
</tls-crypt>
server $this->network $this->netmask
#mode server
#ifconfig 10.0.0.254 255.255.255.0
topology subnet
client-config-dir ccd
ccd-exclusive
float
keepalive 10 60
opt-verify
user nobody
group nogroup
persist-key
persist-tun
tls-version-min 1.2
tls-version-max 1.3
cipher AES-128-GCM
ncp-disable
tls-ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
tls-cipher TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA512
dh none
ecdh-curve secp521r1
tls-server
remote-cert-tls client
verify-client-cert require
tls-cert-profile preferred
EOT;
	}

	private function generate_client_conf($ca, $cert, $key, $tls_crypt)
	{
		return <<<EOT
client
proto $this->protocol
port $this->server_port
remote $this->server_address
dev tun
verb 5
<ca>
$ca
</ca>
<cert>
$cert
</cert>
<key>
$key
</key>
<tls-crypt>
$tls_crypt
</tls-crypt>
tls-version-min 1.2
tls-version-max 1.3
cipher AES-128-GCM
ncp-disable
tls-ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
tls-cipher TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA512
ecdh-curve secp521r1
tls-client
tls-cert-profile preferred
remote-cert-tls server
auth-nocache
EOT;
	}

}