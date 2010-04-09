use Module::Build;

my $mb = Module::Build->new(
    module_name     => 'Plack::Middleware::Access',
    license         => 'perl',
    dist_author     => 'Yury Zavarin <yury.zavarin@gmail.com>',
    requires        => {
        'Module::Build' => 0.2805,
        'Net::IP'       => 0,
        'Carp'          => 0,
        'Plack'         => 0
    },
    build_requires => {
        'Test::More'     => 0,
        'Plack'          => 0
    }
);

$mb->create_build_script;
