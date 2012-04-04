use Test::More tests => 6;

use strict;
use warnings;

use Digest::Bcrypt;

my $secret = "Super Secret Squirrel";
my $salt   = "   known salt   ";
my $cost   = 1;


eval {
    my $ctx = Digest::Bcrypt->new;

    $ctx->add($secret);
    $ctx->salt($salt);
    $ctx->cost('foobar');
    $ctx->digest;
};

like $@, qr/Cost must be an integer between 1 and 31/i, 'Dies on non-numeric cost';


eval {
    my $ctx = Digest::Bcrypt->new;

    $ctx->add($secret);
    $ctx->salt($salt);
    $ctx->cost(32);
    $ctx->digest;
};

like $@, qr/Cost must be an integer between 1 and 31/i, 'Dies on too large a cost';


eval {
    my $ctx = Digest::Bcrypt->new;

    $ctx->add($secret);
    $ctx->salt($salt);
    $ctx->cost(-1);
    $ctx->digest;
};

like $@, qr/Cost must be an integer between 1 and 31/i, 'Dies on too small a cost';


eval {
    my $ctx = Digest::Bcrypt->new;

    $ctx->add($secret);
    $ctx->digest;
};

like $@, qr/Cost must be an integer between 1 and 31/i, 'Dies when no cost specified';


eval {
    my $ctx = Digest::Bcrypt->new;

    $ctx->add($secret);
    $ctx->salt('too small');
    $ctx->cost($cost);
    $ctx->digest;
};

like $@, qr/Salt must be exactly 16 octets long/i, 'Dies on incorrect amount of salt';


eval {
    my $ctx = Digest::Bcrypt->new;

    $ctx->add($secret);
    $ctx->cost($cost);
    $ctx->digest;
};

like $@, qr/Salt must be exactly 16 octets long/i, 'Dies when no salt specified';
