package Net::Whois::Gateway::Client;

use strict;
use POE qw(Component::Client::TCP Filter::Reference);
#use Data::Dumper;
use Carp;

our $VERSION = 0.06;
our $DEBUG = 0;

our %POSTPROCESS;
our $default_host = "localhost";
our $default_port = 54321;
our @answer;

# get whois info from gateway
# %param: queries*, params
sub whois {    
    my %params = @_;
    my $gateway_host = delete $params{gateway_host} || $default_host;
    my $gateway_port = delete $params{gateway_port} || $default_port;
    
    @answer = ();
    POE::Component::Client::TCP->new(
        RemoteAddress => $gateway_host,
        RemotePort    => $gateway_port,
        Filter        => "POE::Filter::Reference",
        Connected     => \&send_whois_request,
        ConnectError  => \&connection_error,
        ServerInput   => \&got_answer,
        Started       => \&starting_client,
        Args          => [ \%params ],
    );
    $poe_kernel->run();
    @answer = apply_postprocess(@answer);
    return @answer;
}

# client starts
sub starting_client {
    my ($heap, $params) = @_[HEAP, ARG0];
    $heap->{params}  = $params;
}

# send request to gateway
sub send_whois_request {
    my $heap = $_[HEAP];
    #print "connected to $host:$port ...\n" if $DEBUG;
    $heap->{server}->put( [$heap->{params}] );
};

# error connectiong to gateway
sub connection_error{
    my ($kernel) = $_[KERNEL];
    die "could not connect to server";
    @answer = ();
    $kernel->yield('shutdown');
}

# gateway answers
sub got_answer {
    my ($kernel, $heap, $input) = @_[KERNEL, HEAP, ARG0];
    @answer = @$input;
    $kernel->yield('shutdown');    
}

sub apply_postprocess {
    my @all_results = @_;
    my @out_results;
    
    foreach my $result ( @all_results ) {
        my $server = $result->{server};
        if ($result->{whois} && defined $POSTPROCESS{$server}) {
            $result->{whois} = $POSTPROCESS{$server}->($result->{whois});
        }
        push @out_results, $result;
    }
    
    return @out_results;
}

1;
__END__

=head1 NAME

Net::Whois::Gateway::Client - Interface to Net::Whois::Gateway::Server

=head1 SYNOPSIS

    use strict;
    use Net::Whois::Gateway::Client;
    
    my @all_results = Net::Whois::Gateway::Client::whois( query => ['reg.ru', 'yandex.ru'] );
    
    # or
    
    my @domains = qw(
        yandex.ru
        rambler.ru
        reg.ru
        google.com    
    );
    
    my @all_results = Net::Whois::Gateway::Client::whois(
        query        => \@domains,
        gateway_host => '192.168.0.5',    # default 'localhost'
        gateway_port => '888',            # default 54321
        referral     => 0,                # default 1
        server       => 'whois.ripn.net', # default try to auto-determine
        omit_msg     => 0,                # default 2
        use_cnames   => 1,                # default 0
        timeout      => 60,               # default 30
        local_ips    => ['192.168.0.1'],  # default use default ip
        cache_dir    => '~/whois_temp',   # default '/tmp/whois-gateway-d'
        cache_time   => 5,                # default 1
    );

    foreach my $result ( @all_results ) {
        my $query = $result->{query} if $result;
        if ($result->{error}) {
            print "Can't resolve WHOIS-info for ".$result->{query}."\n";
        } else {
            print "QUERY: ".$result->{query}."\n";
            print "WHOIS: ".$result->{whois}."\n";
            print "SERVER: ".$result->{server}."\n";
        };
    }                            

=head1 DESCRIPTION

Net::Whois::Gateway::Client - it's an interface to Net::Whois::Gateway::Server,
which  provides a very quick way to get WHOIS-info for list of domains, IPs or registrars.
Internally uses POE to run parallel non-blocking queries to whois-servers.
Supports recursive queries, cache, queries to HTTP-servers.

You definitely need install Net::Whois::Gateway::Server first, to use Net::Whois::Gateway::Client.

=head1 Functions

=over

=item whois()

whois( query => \@query_list [, param => $value] )
Get whois-info for list of queries. One argument is required and some optional:

=back

=head1 whois() parameters

=over 2

=item query

query is an arrayref of domains, ips or registrars to send to
whois server. Required.

=item gateway_host

Host to connect. Whois-gateway should be running there.
Default 'localhost';

=item gateway_port

Port to connect. Default 54321;

=item server

Specify server to connect. Defaults try to be determined by the component. Optional.

=item referral

Optional.

0 - make just one query, do not follow if redirections can be done;

1 - follow redirections if possible, return last response from server; # default

2 - follow redirections if possible, return all responses;


Exapmle:
    my @all_results = Net::Whois::Gateway::Client::whois(
        query    => [ 'google.com', 'godaddy.com' ],
        referral => 2,
    );
    foreach my $result ( @all_results ) {
        my $query = $result->{query} if $result;
        if ($result->{error}) {
            print "Can't resolve WHOIS-info for ".$result->{query}."\n";
        } else {
            print "Query for: ".$result->{query}."\n";
            # process all subqueries
            my $count = scalar @{$result->{subqueries}};
            print "There were $count queries:\n";
            foreach my $subquery (@{$result->{subqueries}}) {
                print "\tTo server ".$subquery->{server}."\n";
                # print "\tQuery: ".$subquery->{query}."\n";
                # print "\tResponse:\n".$subquery->{whois}."\n";
            }
        }
    }                       

=item omit_msg

0 - give the whole response;

1 - attempt to strip several known copyright messages and disclaimers;

2 - will try some additional stripping rules if some are known for the spcific server.

Default is 2.

=item use_cnames

Use whois-servers.net to get the whois server name when possible.
Default is to use the hardcoded defaults.

=item timeout

Cancel the request if connection is not made within a specific number of seconds.
Default 30 sec.

=item local_ips

List of local IP addresses to use for WHOIS queries.
Addresses will be used used successively in the successive queries
Default SRS::Comm::get_external_interfaces_ips()

=item cache_dir

Whois information will be cached in this directory.
Default '/tmp/whois-gateway-d'.

=item cache_time

Number of minutes to save cache. Default 1 minute.

=head1 Postrprocessing

Call to a user-defined subroutine on each whois result depending on whois-server supported:

    $Net::Whois::Gateway::Client::POSTPROCESS{whois.crsnic.net} = \&my_func;

=head1 AUTHOR

Sergey Kotenko <graykot@gmail.com>

=head1 SEE ALSO

Net::Whois::Gateway::Server L<http://search.cpan.org/perldoc?Net::Whois::Gateway::Server>
