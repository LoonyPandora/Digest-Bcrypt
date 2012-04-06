use Test::More tests => 8;

use strict;
use warnings;

use Digest;
use Digest::Bcrypt;

my $secret = "Super Secret Squirrel";
my $salt   = "   known salt   ";
my $cost   = 1;

# Object is reset after each hash is generated
my $direct = Digest::Bcrypt->new;


$direct->add($secret);
$direct->salt($salt);
$direct->cost($cost);

ok($direct->digest, "Creates Binary Digest");


$direct->add($secret);
$direct->salt($salt);
$direct->cost($cost);

ok($direct->hexdigest eq '7ca73fd67f694324bcad7b0910093ff8ef9e8c564e2297', "Creates Hex Digest");


$direct->add($secret);
$direct->salt($salt);
$direct->cost($cost);

ok($direct->b64digest eq 'fKc/1n9pQyS8rXsJEAk/+O+ejFZOIpc', "Creates Base 64 Digest");


$direct->add($secret);
$direct->salt($salt);
$direct->cost($cost);

ok($direct->bcrypt_b64digest eq 'dIa9zl7nOwQ6pVqHC.i98M8chDXMGna', "Creates Bcrypt Base 64 Digest");


# Object is reset after each hash is generated
my $indirect = Digest->new('Bcrypt');


$indirect->add($secret);
$indirect->salt($salt);
$indirect->cost($cost);

ok($indirect->digest, "Creates Indirect Binary Digest");


$indirect->add($secret);
$indirect->salt($salt);
$indirect->cost($cost);

ok($indirect->hexdigest eq '7ca73fd67f694324bcad7b0910093ff8ef9e8c564e2297', "Creates Indirect Hex Digest");


$indirect->add($secret);
$indirect->salt($salt);
$indirect->cost($cost);

ok($indirect->b64digest eq 'fKc/1n9pQyS8rXsJEAk/+O+ejFZOIpc', "Creates Indirect Base 64 Digest");


$indirect->add($secret);
$indirect->salt($salt);
$indirect->cost($cost);

ok($indirect->bcrypt_b64digest eq 'dIa9zl7nOwQ6pVqHC.i98M8chDXMGna', "Creates Indirect Bcrypt Base 64 Digest");
