use Test::More tests => 3;

use strict;
use warnings;

use Digest::Bcrypt;

my $secret = "Super Secret Squirrel";
my $salt   = "   known salt   ";
my $cost   = 1;

# Object is reset after each hash is generated
my $ctx = Digest::Bcrypt->new;

can_ok($ctx, qw/new clone add digest hexdigest b64digest bcrypt_b64digest salt reset/);

$ctx->add($secret);
$ctx->salt($salt);
$ctx->cost($cost);

ok($ctx->salt eq $salt, "Reads salt correctly");
ok($ctx->cost == $cost, "Reads cost correctly");
