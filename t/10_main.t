use strict;

use Plack::Builder;
use Plack::Test;

use Test::More;

my @tests = (
    {
     status => 200
    },
    {
     rules => [ deny => '127.0.0.1' ],
     status => 403
    },
    {
     rules => [ deny => 'all', allow => '127.0.0.1' ],
     status => 403
    },
    {
     rules => [ allow => '127.0.0.1', deny => 'all' ],
     status => 200
    },
    {
     rules => [ deny => 'localhost' ],
     status => 403
    },
    {
     rules => [ deny => sub { shift()->{REMOTE_ADDR} =~ /7/ } ],
     status => 403
    },
    {
     rules => [ deny => '127.0.0.1' ],
     deny_page => sub { return [ 401, [ 'Content-Type' => 'text/plain' ], ['custom']] },
     status => 401,
     content => 'custom',
    },
    {
     rules => [ deny => '127.0.0.1' ],
     deny_page => 'something',
     status => 403,
     content => 'something',
    },
    {
     rules => [ allow => 'nosuchhost.com', # this rule should be skipped
                allow => sub { shift()->{REMOTE_ADDR} =~ /7/ }, # this rule should work
                deny  => 'all' ],
     status => 200
    },
    {
     rules => [ deny => '127.0.0.1', allow => '::1', deny => 'all' ],
     status => 200,
     remote_addr => '::1',
    },
    {
     rules => [ allow => '127.0.0.1', deny => '::1', allow => 'all' ],
     status => 403,
     remote_addr => '::1',
    },
    {
     rules => [ deny => "2001:db8:1:2::/64", allow => "2001:db8::/32", deny => "all" ],
     status => 403,
     remote_addr => '2001:db8:1:2::1',
    },
    {
     rules => [ deny => "2001:db8:1:2::/64", allow => "2001:db8::/32", deny => "all" ],
     status => 200,
     remote_addr => '2001:db8::1',
    }
);

foreach my $test (@tests) {
    my $app = get_handler($test->{rules}, $test->{deny_page}, $test->{remote_addr});

    test_psgi app => $app, client => sub {
        my $cb = shift;

        my $res = $cb->(HTTP::Request->new(GET => 'http://localhost/'));
        is( $res->code, $test->{status} ) if $test->{status};
        is( $res->content, $test->{content} ) if $test->{content};
    };
}

done_testing;

sub get_handler {
    my ($rules, $deny_page, $remote_addr) = @_;
    my $base_app = builder {
        enable "Plack::Middleware::Access", rules => $rules, deny_page => $deny_page;
        sub {
            return [ 200, [ 'Content-Type' => 'plain/text' ], ['hello there']];
        };
    };
    my $app = sub {
        my $env = shift;
        if (defined($remote_addr)) {
            $env->{REMOTE_ADDR} = $remote_addr;
        }
        $base_app->($env);
    };
}
