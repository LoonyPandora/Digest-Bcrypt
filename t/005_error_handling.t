use Test::More tests => 4;

use strict;
use warnings;

use Digest::Bcrypt;

my $secret = "Super Secret Squirrel";
my $salt   = "   known salt   ";
my $cost   = 1;

# Object is reset after each hash is generated
my $ctx = Digest::Bcrypt->new;


eval {
    $ctx->add($secret);
    $ctx->salt($salt);
    $ctx->cost('foobar');
    $ctx->digest;
};

like $@, qr/Cost must be an integer between 1 and 31/i, 'Dies on non-numeric cost';


eval {
    $ctx->add($secret);
    $ctx->salt($salt);
    $ctx->cost(32);
    $ctx->digest;
};

like $@, qr/Cost must be an integer between 1 and 31/i, 'Dies on too large a cost';


eval {
    $ctx->add($secret);
    $ctx->salt($salt);
    $ctx->cost(-1);
    $ctx->digest;
};

like $@, qr/Cost must be an integer between 1 and 31/i, 'Dies on too small a cost';


eval {
    $ctx->add($secret);
    $ctx->salt('too small');
    $ctx->cost($cost);
    $ctx->digest;
};

like $@, qr/Salt must be exactly 16 octets long/i, 'Dies on incorrect amount of salt';

