#!/usr/bin/perl -w
use strict;
use Test::More;

# data for tests
my @domains = qw(     
    freshmeat.net
    freebsd.org
    reg.ru
    ns1.nameself.com.NS
    perl.com
);

my @domains_not_reg = qw(
    thereisnosuchdomain123.com
    thereisnosuchdomain453.ru
);

my @ips = qw( 87.242.73.95 );

my @registrars = ('REGRU-REG-RIPN');
my $server  = 'whois.ripn.net',

# start test
my $tests_qty =  @domains + @domains_not_reg + @ips + @registrars;
plan tests    => 1 + $tests_qty;

use_ok('Net::Whois::Gateway::Client');

SKIP: {
    print "The following tests requires whois-gateway-d runned...\n";
    my $daemon_runned;
    eval {
        $daemon_runned = `ps -e | grep "whois-gateway-d"`;
    };        
    skip "No whois-gateway-d detected...", $tests_qty
        if $@ || !$daemon_runned;
    
    my @full_result = Net::Whois::Gateway::Client::whois(
        query => \@domains,
    );
    foreach my $result ( @full_result ) {
        my $query = $result->{query} if $result;
        $query =~ s/.NS$//i;
        ok( $result && !$result->{error} && $result->{whois} =~ /$query/i,
            "whois for domain ".$result->{query}." from ".$result->{server} );
    }
    
    
    @full_result = Net::Whois::Gateway::Client::whois(
        query => \@registrars,
        server => $server,
    );
    foreach my $result ( @full_result ) {
        my $query = $result->{query} if $result;
        ok( $result && !$result->{error} && $result->{whois} =~ /$query/i,
            "whois for registrar  ".$result->{query}." from ".$result->{server} );
    }

    @full_result = Net::Whois::Gateway::Client::whois(
        query => \@domains_not_reg,
    );
    foreach my $result ( @full_result ) {
        ok( $result && $result->{error},
            "whois for domain (not reged) ".$result->{query} );
    }
    
    @full_result = Net::Whois::Gateway::Client::whois(    
        query  => \@ips,
    );
    foreach my $result ( @full_result ) {
        ok( $result && !$result->{error} && $result->{whois},
            "whois for IP ".$result->{query}." from ".$result->{server} );
    }    
}

1;

