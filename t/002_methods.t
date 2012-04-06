use Test::More tests => 12;

use strict;
use warnings;

use Digest;
use Digest::Bcrypt;

my $secret = "Super Secret Squirrel";
my $salt   = "   known salt   ";
my $cost   = 1;


my $direct = Digest::Bcrypt->new;

can_ok($direct, qw/new clone add digest hexdigest b64digest bcrypt_b64digest salt reset/);

$direct->add($secret);
$direct->salt($salt);
$direct->cost($cost);

ok($direct->salt eq $salt, "Reads salt correctly");
ok($direct->cost == $cost, "Reads cost correctly");


my $direct_clone = $direct->clone;
$direct_clone->salt('  unknown salt  ');
$direct_clone->cost('2');

ok($direct->salt ne $direct_clone->salt, "Cloned object has different salt");
ok($direct->cost != $direct_clone->cost, "Cloned object has different cost");
ok($direct->hexdigest ne $direct_clone->hexdigest, "Cloned object produces different hash");



my $indirect = Digest->new('Bcrypt');
can_ok($indirect, qw/new clone add digest hexdigest b64digest bcrypt_b64digest salt reset/);

$indirect->add($secret);
$indirect->salt($salt);
$indirect->cost($cost);

ok($indirect->salt eq $salt, "Indirect object reads salt correctly");
ok($indirect->cost == $cost, "Indirect object reads cost correctly");



my $indirect_clone = $indirect->clone;
$indirect_clone->salt('  unknown salt  ');
$indirect_clone->cost('2');

ok($indirect->salt ne $indirect_clone->salt, "Indirect cloned object has different salt");
ok($indirect->cost != $indirect_clone->cost, "Indirect cloned object has different cost");
ok($indirect->hexdigest ne $indirect_clone->hexdigest, "Indirect cloned object produces different hash");
