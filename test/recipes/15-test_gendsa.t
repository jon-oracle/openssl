#! /usr/bin/env perl
# Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir bldtop_file/;
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_gendsa");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "This test is unsupported in a no-dsa build"
    if disabled("dsa");

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

plan tests =>
    ($no_fips ? 0 : 5)          # FIPS install test + fips related tests
    + 10;

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'type:fips186_4',
             '-text'])),
   "genpkey DSA params fips186_4 with verifiable g");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'type:fips186_4',
             '-text'])),
   "genpkey DSA params fips186_4 with unverifiable g");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'type:fips186_2',
             '-text'])),
   "genpkey DSA params fips186_2");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'type:fips186_2',
             '-pkeyopt', 'dsa_paramgen_bits:1024',
             '-out', 'dsagen.legacy.pem'])),
   "genpkey DSA params fips186_2 PEM");

ok(!run(app([ 'openssl', 'genpkey', '-algorithm', 'DSA',
             '-pkeyopt', 'type:group',
             '-text'])),
   "genpkey DSA does not support groups");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'type:fips186_4',
             '-out', 'dsagen.pem'])),
   "genpkey DSA params fips186_4 PEM");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'pbits:2048',
             '-pkeyopt', 'qbits:256',
             '-pkeyopt', 'type:fips186_4',
             '-outform', 'DER',
             '-out', 'dsagen.der'])),
   "genpkey DSA params fips186_4 DER");

ok(run(app([ 'openssl', 'genpkey',
             '-paramfile', 'dsagen.legacy.pem',
             '-pkeyopt', 'type:fips186_2',
             '-text'])),
   "genpkey DSA fips186_2 with PEM params");

# The seed and counter should be the ones generated from the param generation
# Just put some dummy ones in to show it works.
ok(run(app([ 'openssl', 'genpkey',
             '-paramfile', 'dsagen.der',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'hexseed:0102030405060708090A0B0C0D0E0F1011121314',
             '-pkeyopt', 'pcounter:25',
             '-text'])),
   "genpkey DSA fips186_4 with DER params");

ok(!run(app([ 'openssl', 'genpkey',
              '-algorithm', 'DSA'])),
   "genpkey DSA with no params should fail");

sub genparam_fips {
    my ($pbits, $qbits, @prov) = @_;

    ok(run(app(['openssl', 'genpkey',
                @prov,
               '-genparam',
               '-algorithm', 'DSA',
               '-pkeyopt', "pbits:$pbits",
               '-pkeyopt', "qbits:$qbits",
               '-out', "dsa-$pbits-$qbits-params.pem"])),
       "Generating DSA params with $pbits-bit P, $qbits-bit Q");
}

sub genpkey_fips {
    my ($pbits, $qbits, @prov) = @_;

    ok(run(app(['openssl', 'genpkey',
                @prov,
               #'-algorithm', 'DSA',
               '-paramfile', "dsa-$pbits-$qbits-params.pem",
               #'-pkeyopt', 'type:fips186_4',
               '-text',
               '-out', "dsa-$pbits-$qbits-key.pem"])),
       "Generating DSA keypair with $pbits-bit P, $qbits-bit Q");
}

unless ($no_fips) {
    my $provconf = srctop_file("test", "fips-and-base.cnf");
    my $provpath = bldtop_dir("providers");
    my @prov = ( "-provider-path", $provpath,
                 "-config", $provconf);
    my $infile = bldtop_file('providers', platform->dso('fips'));

    ok(run(app(['openssl', 'fipsinstall',
                '-out', bldtop_file('providers', 'fipsmodule.cnf'),
                '-module', $infile,
                '-provider_name', 'fips', '-mac_name', 'HMAC',
                '-section_name', 'fips_sect'])),
       "fipsinstall");

    $ENV{OPENSSL_TEST_LIBCTX} = "1";

    genparam_fips(2048, 256, @prov);
    genparam_fips(3072, 256, @prov);

    genpkey_fips(2048, 256, @prov);
    genpkey_fips(3072, 256, @prov);


}
