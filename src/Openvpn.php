<?php

namespace Paranic;

class Openvpn {

	public $server_address = '127.0.0.1';
	public $server_port = '1194';
	public $protocol = 'udp';
	public $easy_rsa_folder = '/tmp/easy-rsa';
	public $network = '10.0.0.0';
	public $netmask = '255.255.255.0';

	public function setup()
	{
		// Check if debian version is 8.2
		if (is_file('/etc/debian_version') AND $ver = file_get_contents('/etc/debian_version'))
		{
			if (trim($ver) !== '8.2')
			{
				die('Invalid operating system or version.' . PHP_EOL);
			}
		} 

		// Check if we have openvpn package installed
		if (strlen(exec('dpkg -l openvpn')) == 0)
		{
			die('openvpn package is not installed.' . PHP_EOL);
		}

		// Check if we have easy-rsa package installed
		if (strlen(exec('dpkg -l easy-rsa')) == 0)
		{
			die('easy-rsa package is not installed.' . PHP_EOL);
		}

		// Check if folder is available
		if (file_exists($this->easy_rsa_folder))
		{
			die('Cannot setup to ' . $this->easy_rsa_folder . ', an item already exists.' . PHP_EOL);
		}

		// Create easy-rsa and required directories
		shell_exec('/usr/bin/make-cadir ' . $this->easy_rsa_folder);
		$easy_rsa_path = realpath($this->easy_rsa_folder);
		shell_exec('mkdir ' . $easy_rsa_path . '/keys');
		shell_exec('mkdir ' . $easy_rsa_path . '/keys_packed');

		// Replace default 2048 key size variable to 4096
		$vars = file_get_contents($easy_rsa_path . '/vars');
		$vars = str_replace('KEY_SIZE=2048', 'KEY_SIZE=4096', $vars);
		file_put_contents($easy_rsa_path . '/vars', $vars);

		// Do a clean-all so that required index files are created
		shell_exec('cd ' . $easy_rsa_path . ' && . ./vars && ./clean-all');

		// Generate Diffie-Hellman PEM
		shell_exec('openssl dhparam 4096 > ' . $easy_rsa_path . '/keys/dh4096.pem');
		
		// Generate the HMAC key file
		shell_exec('openvpn --genkey --secret ' . $easy_rsa_path . '/keys/ta.key');

		// Generate Certificate Authority
		shell_exec('cd ' . $easy_rsa_path . ' && . ./vars && ./pkitool --initca');

		return TRUE;
	}

	public function create_server()
	{
		// Check if we easy-rsa folder exists
		$easy_rsa_path = realpath($this->easy_rsa_folder);
		if (!$easy_rsa_path) die('Please invoke setup() first.' . PHP_EOL);

		// Check if we already created server
		if (in_array('server', $this->existing_keys())) die('Server already created.' . PHP_EOL);

		shell_exec('cd ' . $easy_rsa_path . ' && . ./vars && ./pkitool --server server');
		shell_exec('mkdir ' . $easy_rsa_path . '/keys_packed/server');
		shell_exec('cp ' . $easy_rsa_path . '/keys/ca.crt ' . $easy_rsa_path . '/keys_packed/server/');
		shell_exec('cp ' . $easy_rsa_path . '/keys/server.crt ' . $easy_rsa_path . '/keys_packed/server/');
		shell_exec('cp ' . $easy_rsa_path . '/keys/server.key ' . $easy_rsa_path . '/keys_packed/server/');
		shell_exec('cp ' . $easy_rsa_path . '/keys/dh4096.pem ' . $easy_rsa_path . '/keys_packed/server/');
		shell_exec('cp ' . $easy_rsa_path . '/keys/ta.key ' . $easy_rsa_path . '/keys_packed/server/');

		$server_conf = $this->generate_server_conf();

		file_put_contents($easy_rsa_path . '/keys_packed/server/server.conf', $server_conf);

		shell_exec('cd ' . $easy_rsa_path . '/keys_packed && tar -czf server.tar.gz server');

		return TRUE;
	}

	public function create_client($client_name = NULL)
	{
		// Check if we easy-rsa folder exists
		$easy_rsa_path = realpath($this->easy_rsa_folder);
		if (!$easy_rsa_path) die('Please invoke setup() first.' . PHP_EOL);

		// Check client_name
		if (is_null($client_name) OR empty($client_name)) die('Please input client name that you want to create.' . PHP_EOL);

		// Check if client_name exists in our keys database
		if (in_array($client_name, $this->existing_keys())) die('Client name already exists in database.' . PHP_EOL);

		shell_exec('cd ' . $easy_rsa_path . ' && . ./vars && ./pkitool ' . $client_name);
		shell_exec('mkdir ' . $easy_rsa_path . '/keys_packed/' . $client_name);
		shell_exec('cp ' . $easy_rsa_path . '/keys/ca.crt ' . $easy_rsa_path . '/keys_packed/' . $client_name . '/');
		shell_exec('cp ' . $easy_rsa_path . '/keys/' . $client_name . '.crt ' . $easy_rsa_path . '/keys_packed/' . $client_name . '/client.crt');
		shell_exec('cp ' . $easy_rsa_path . '/keys/' . $client_name . '.key ' . $easy_rsa_path . '/keys_packed/' . $client_name . '/client.key');
		shell_exec('cp ' . $easy_rsa_path . '/keys/ta.key ' . $easy_rsa_path . '/keys_packed/' . $client_name . '/');

		$client_conf = $this->generate_client_conf();

		file_put_contents($easy_rsa_path . '/keys_packed/' . $client_name . '/client.conf', $client_conf);

		shell_exec('cd ' . $easy_rsa_path . '/keys_packed && tar -czf ' . $client_name . '.tar.gz ' . $client_name);

		// Generate single file inline config
		$client_conf_inline = $this->create_client_conf_inline($client_name);
		file_put_contents($easy_rsa_path . '/keys_packed/' . $client_name . '_inline.conf', $client_conf_inline);
	}

	public function existing_keys()
	{
		// Check if we easy-rsa folder exists
		$easy_rsa_path = realpath($this->easy_rsa_folder);
		if (!$easy_rsa_path) die('Please invoke setup() first.' . PHP_EOL);

		$existing_keys = [];
		foreach (new \DirectoryIterator($easy_rsa_path . '/keys_packed') as $file_info)
		{
			if ($file_info->isDot() OR $file_info->isFile()) continue;

			array_push($existing_keys, $file_info->getBasename());
		}

		return $existing_keys;
	}

	public function create_client_conf_inline($client_name = NULL)
	{
		// Check if we easy-rsa folder exists
		$easy_rsa_path = realpath($this->easy_rsa_folder);
		if (!$easy_rsa_path) die('Please invoke setup() first.' . PHP_EOL);

		// Check client_name
		if (is_null($client_name) OR empty($client_name)) die('Please input client name.' . PHP_EOL);

		$client_key_folder = $easy_rsa_path . '/keys_packed/' . $client_name;
		if (!is_dir($client_key_folder)) die('Client folder not found.' . PHP_EOL);

		$ca_crt = trim(file_get_contents($client_key_folder . '/ca.crt'));

		$client_crt = trim(file_get_contents($client_key_folder . '/client.crt'));
		preg_match('/(-----BEGIN CERTIFICATE-----)(?s)(.*?)(-----END CERTIFICATE-----)/', $client_crt, $match);
		$client_crt = $match[0];

		$client_key = trim(file_get_contents($client_key_folder . '/client.key'));
		
		$ta_key = trim(file_get_contents($client_key_folder . '/ta.key'));
		preg_match('/(-----BEGIN OpenVPN Static key V1-----)(?s)(.*?)(-----END OpenVPN Static key V1-----)/', $ta_key, $match);
		$ta_key = $match[0];

		return $this->generate_client_conf_inline($ca_crt, $client_crt, $client_key, $ta_key);
	}

	private function generate_server_conf()
	{
		return <<<EOT
port $this->server_port
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh4096.pem
tls-auth ta.key 0
server $this->network $this->netmask
ifconfig-pool-persist ipp.txt
client-config-dir ccd
ccd-exclusive
client-to-client
keepalive 10 120
persist-key
persist-tun
status openvpn-status.log
verb 3
cipher AES-256-CBC
auth SHA512
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA
EOT;

	}

	private function generate_client_conf()
	{
		return <<<EOT
client
dev tun
proto tcp
remote $this->server_address $this->server_port
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
ns-cert-type server
verb 3
cipher AES-256-CBC
auth SHA512
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA
EOT;
	
	}

	private function generate_client_conf_inline($ca_crt, $client_crt, $client_key, $ta_key)
	{
		return <<<EOT
client
dev tun
proto tcp
remote $this->server_address $this->server_port
resolv-retry infinite
nobind
persist-key
persist-tun
<ca>
$ca_crt
</ca>
<cert>
$client_crt
</cert>
<key>
$client_key
</key>
key-direction 1
<tls-auth>
$ta_key
</tls-auth>
ns-cert-type server
verb 3
cipher AES-256-CBC
auth SHA512
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA
EOT;

	}

}