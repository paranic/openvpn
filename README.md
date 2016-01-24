# PHP Openvpn

A PHP library to generate openvpn keys and configurations.

Based on security considerations taken from:
- https://community.openvpn.net/openvpn/wiki/Hardening
- https://blog.g3rt.nl/openvpn-security-tips.html


## Notes
works on debian 8.2 jessie with openvpn package installed.
```
apt-get install openvpn
```

## Usage
### Create Instance
After including the library with autoloader or manualy, you can initiate and configure the class.
```
$openvpn = new Paranic\Openvpn();
$openvpn->server_address = '127.0.0.1';
$openvpn->server_port = '1194';
$openvpn->protocol = 'udp';
$openvpn->easy_rsa_folder = '/tmp/easy-rsa';
$openvpn->network = '10.0.0.0';
$openvpn->netmask = '255.255.255.0';
```
All keys generated will be stored in the easy_rsa_folder under keys_packed.

### Setup easy-rsa
```
$openvpn->setup();
```
This is going to take some time, creating required keys for the first time.

### Generate Server Configuration
```
$openvpn->create_server();
```
Again your server configuration is stored at easy_rsa_folder under the keys_packed subfolder.

### Generate Client Configuration
```
$openvpn->create_client('sample_client_1');
```
You can create many clients and get theyr configuration in the keys_packed folder, including a all in one inline client config file.