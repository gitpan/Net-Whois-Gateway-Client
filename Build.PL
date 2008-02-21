#!/usr/bin/perl -w
use strict;
use Module::Build;

my $build = Module::Build->new(
    module_name => 'Net::Whois::Gateway::Client',
    license  => 'perl',
    requires => {
	'POE' => 0,
	'POE::Component::Client::TCP' => 0,
	'POE::Filter::Reference' => 0, 
    },
    create_makefile_pl => 'traditional',
);

$build->create_build_script;
