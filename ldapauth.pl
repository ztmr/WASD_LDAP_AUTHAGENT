#!/usr/bin/env perl
#
# $Id: $
#
# Module:  ldapauth -- description
# Created: 07-JAN-2010 17:28
# Author:  tmr
#

use strict;
use warnings;

use Authen::Simple::LDAP;

my $ldap = new Authen::Simple::LDAP (
        host    => 'ldap.example.org',
        basedn  => 'dc=example,dc=org'
);

printf "\n *** Central Authentification Service ***\n\n";
printf "Login: "; chomp (my $login = <STDIN>);
printf "Password: "; chomp (my $password = <STDIN>);

if ($ldap->authenticate ($login, $password)) {
  print "Welcome to the show!\n";
}
else { print "Fuck you!\n"; }

# vim: fdm=syntax:fdn=3:tw=74:ts=2:syn=perl
