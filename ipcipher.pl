#!/usr/bin/perl
# 
# Encrypt IPv6/IPv4 address to a valid address
# Use: ipcipher.pl -[e|d] <IPv6|IPv4>
#
# Spec from ipcipher
#      https://github.com/PowerDNS/ipcipher
#
# v4 version based on original ipcrypt python version from
# Jean-Philippe Aumasson
#      https://github.com/veorq/ipcrypt
#
# Author: Hugo Salgado <hsalgado@vulcano.cl>
#
use strict;
use warnings;

my $KEY = 'some 16-byte key';

use Crypt::Cipher::AES;
use Net::IP qw(:PROC);

use Getopt::Std;

sub xor4 {
    my $ps = shift;
    my $pk = shift;

    my @out;
    foreach my $i (0..3) {
        push @out, ($ps->[$i] ^ $pk->[$i]) & 0xff; 
    }

    return @out;
}

sub rotl {
    my ($b, $r) = @_;

    return (($b << $r) & 0xff) | ($b >> (8 - $r));
}

sub permute_fwd {
    my $b = shift;

    $b->[0] += $b->[1];
    $b->[2] += $b->[3];
    $b->[0] &= 0xff;
    $b->[2] &= 0xff;
    $b->[1] = &rotl($b->[1], 2);
    $b->[3] = &rotl($b->[3], 5);
    $b->[1] ^= $b->[0];
    $b->[3] ^= $b->[2];
    $b->[0] = &rotl($b->[0], 4);
    $b->[0] += $b->[3];
    $b->[2] += $b->[1];
    $b->[0] &= 0xff;
    $b->[2] &= 0xff;
    $b->[1] = &rotl($b->[1], 3);
    $b->[3] = &rotl($b->[3], 7);
    $b->[1] ^= $b->[2];
    $b->[3] ^= $b->[0];
    $b->[2] = &rotl($b->[2], 4);

    return $b;
}

sub permute_bwd {
    my $b = shift;

    $b->[2] = &rotl($b->[2], 4);
    $b->[1] ^= $b->[2];
    $b->[3] ^= $b->[0];
    $b->[1] = &rotl($b->[1], 5);
    $b->[3] = &rotl($b->[3], 1);
    $b->[0] -= $b->[3];
    $b->[2] -= $b->[1];
    $b->[0] &= 0xff;
    $b->[2] &= 0xff;
    $b->[0] = &rotl($b->[0], 4);
    $b->[1] ^= $b->[0];
    $b->[3] ^= $b->[2];
    $b->[1] = &rotl($b->[1], 6);
    $b->[3] = &rotl($b->[3], 3);
    $b->[0] -= $b->[1];
    $b->[2] -= $b->[3];
    $b->[0] &= 0xff;
    $b->[2] &= 0xff;

    return $b;
}

sub encrypt {
    my ($key, $ip) = @_;

    my @key = map {unpack('C', $_) } split //, $key;
    my @state = split /\./, $ip;

    my @pedazo = @key[0..3];
    @state = &xor4(\@state, \@pedazo);
    @state = @{&permute_fwd(\@state)};
    @pedazo = @key[4..7];
    @state = &xor4(\@state, \@pedazo);
    @state = @{&permute_fwd(\@state)};
    @pedazo = @key[8..11];
    @state = &xor4(\@state, \@pedazo);
    @state = @{&permute_fwd(\@state)};
    @pedazo = @key[12..15];
    @state = &xor4(\@state, \@pedazo);

    return join '.', @state;
}

sub decrypt {
    my ($key, $ip) = @_;

    my @key = map {unpack('C', $_) } split //, $key;
    my @state = split /\./, $ip;

    my @pedazo = @key[12..15];
    @state = &xor4(\@state, \@pedazo);
    @state = @{&permute_bwd(\@state)};
    @pedazo = @key[8..11];
    @state = &xor4(\@state, \@pedazo);
    @state = @{&permute_bwd(\@state)};
    @pedazo = @key[4..7];
    @state = &xor4(\@state, \@pedazo);
    @state = @{&permute_bwd(\@state)};
    @pedazo = @key[0..3];
    @state = &xor4(\@state, \@pedazo);

    return join '.', @state;
}

our($opt_e, $opt_d);
my $out;

getopts('ed');
my $ipin = shift;

my $ipvx = new Net::IP($ipin) or die (Net::IP::Error());

if ($ipvx->version == 6) {
    my $c = Crypt::Cipher::AES->new($KEY);

    if ($opt_e) {
        my $ciphertext = $c->encrypt(pack('B*', $ipvx->binip));

        my $enc = new Net::IP(ip_bintoip(unpack('B*', $ciphertext), 6));
        $out = $enc->short;
    }
    elsif ($opt_d) {
        my $plain = $c->decrypt(pack('B*', $ipvx->binip));
        my $dec = new Net::IP(ip_bintoip(unpack('B*', $plain), 6));
        $out = $dec->short;
    }
    else {
        die "You should provide -e (encrypt) or -d (decrypt)";
    }
}
else {
    if ($opt_e) {
        $out = &encrypt($KEY, $ipin);
    }
    elsif ($opt_d) {
        $out = &decrypt($KEY, $ipin);
    }
    else {
        die "You should provide -e (encrypt) or -d (decrypt)";
    }
}

print $out, "\n";

