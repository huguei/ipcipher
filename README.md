# ipcipher
Encrypt IPv6/IPv4 address to a valid address.

Specifications from ipcipher (standardization in progress):
   https://github.com/PowerDNS/ipcipher

v4 version based on original ipcrypt python version from
Jean-Philippe Aumasson
   https://github.com/veorq/ipcrypt

Use:
```
    $ ./ipcipher.pl -e 127.0.0.1
    114.62.227.59
    $ ./ipcipher.pl -e ::1
    3718:8853:1723:6c88:7e5f:2e60:c79a:2bf
```

Dependences: Net::IP, Crypt::Cipher::AES

