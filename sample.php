<?php

require('./src/Openvpn.php');

$openvpn = new Paranic\Openvpn();
$openvpn->server_address = '192.168.0.1';
$openvpn->server_port = '1194';
$openvpn->protocol = 'udp';
$openvpn->easy_rsa_folder = '/projects/openvpn/easy-rsa';
$openvpn->network = '10.0.0.0';
$openvpn->netmask = '255.255.255.0';

$openvpn->setup();

$openvpn->create_server();

for ($i=1; $i <= 253; $i++) {
	$openvpn->create_client('node' . str_pad($i, 3, '0', STR_PAD_LEFT), $i);
}
