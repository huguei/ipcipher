#!/usr/bin/perl
# 
# Encrypt IPv6/IPv4 address to a valid address
# Use: ipcipher.pl -[e|d] <IPv6|IPv4>
#
# NOTE: all the functionality of the original script has
#       been moved to Net::Address::IP::Cipher.
#       This script is kept just for demo.
#
# Please use
#       https://github.com/huguei/p5-Net-Address-IP-Cipher
#  
# Author: Hugo Salgado <hsalgado@vulcano.cl>
#
use strict;
use warnings;

use Net::Address::IP::Cipher;
use Getopt::Std;

our($opt_e, $opt_d);
getopts('ed');

my $ipcipher = Net::Address::IP::Cipher->new(
    password => 'crypto is not a coin'
);

my $ip = shift;

if ($opt_e) {
    print $ipcipher->enc($ip);
}
elsif ($opt_d) {
    print $ipcipher->dec($ip);
}
else {
    die "You should provide -e or -d"
}

