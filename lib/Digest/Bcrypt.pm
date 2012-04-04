package Digest::Bcrypt;

# ABSTRACT: Perl interface to the bcrypt algorithm

=head1 NAME

Digest::Bcrypt - Perl interface to the bcrypt algorithm

=head1 SYNOPSIS

Provides an interface to the bcrypt hash algorithm.

This module subclasses L<Digest::base> and can be used either directly
or through the Digest meta-module. Using the latter is recommended.

It is mostly a wrapper around L<Crypt::Eksblowfish::Bcrypt>.

=head1 USAGE

    # via the Digest module (recommended)
    use Digest;

    my $bcrypt = Digest->new('Bcrypt');

    # $cost is an integer between 1 and 31
    $bcrypt->cost($cost);

    # $salt must be exactly 16 octets long
    $bcrypt->salt($salt);

    $bcrypt->add($data);

    $digest = $bcrypt->digest;
    $digest = $bcrypt->hexdigest;

    # bcrypt uses a non-standard base64 dictionary that replaces + with .
    $digest = $bcrypt->b64digest;

    # [...]

    # Using the module directly (same interface as above)

    use Digest::Bcrypt;

    my $bcrypt = Digest::Bcrypt->new();

=cut

use strict;

use parent 'Digest::base';

use Carp qw(croak);
use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash en_base64);

our $VERSION = '0.1.0';

=head1 METHODS

The object-oriented interface to C<Digest::Bcrypt> is mostly
identical to that of L<Digest>, with a few additions.

Notably you B<must> set a C<salt> exactly 16 octets in length,
and you must provide a C<cost> in the range C<'1'..'31'>

=head2 new

    my $bcrypt = Digest->new('Bcrypt');

Creates a new C<Digest::Bcrypt> object.

You can also use this module directly

    my $bcrypt = Digest::Bcrypt->new();

=cut

sub new {
    my $class = shift;

    return bless {
        _buffer => '',
    }, ref($class) || $class;
}


=head2 clone

    my $bcrypt->clone;

Creates a clone of the C<Digest::Bcrypt> object, and returns it.

=cut

sub clone {
    my $self = shift;

    return bless {
        cost    => $self->cost,
        salt    => $self->salt,
        _buffer => $self->{_buffer},
    }, ref($self);
}

=head2 add

    $bcrypt->add("a"); $bcrypt->add("b"); $bcrypt->add("c");
    $bcrypt->add("a")->add("b")->add("c");
    $bcrypt->add("a", "b", "c");
    $bcrypt->add("abc");

Adds data to the message we are calculating the digest for.

All the above examples have the same effect

=cut

sub add {
    my $self = shift;

    $self->{_buffer} .= join('', @_);

    return $self;
}

=head2 digest

    $bcrypt->digest;

Return the binary digest for the message.

The returned string will be 23 bytes long.

=cut

sub digest {
    my $self = shift;

    return $self->_digest;
}


=head2 hexdigest

    $bcrypt->hexdigest;

Same as L</"digest">, but will return the digest in hexadecimal form.

The C<length> of the returned string will be 46 and will only contain
characters from the ranges C<'0'..'9'> and C<'a'..'f'>.

=cut


=head2 b64digest

    $bcrypt->b64digest;

Same as L</"digest">, but will return the digest base64 encoded.

The C<length> of the returned string will be 31 and will only contain characters 
from the ranges C<'0'..'9'>, C<'A'..'Z'>, C<'a'..'z'>, C<'+'>, and C<'.'>

The base64 encoded string returned is not padded to be a multiple of 4 bytes long.

I<Note:> bcrypt uses it's own non-standard base64 alphabet,
replacing C<'/'> with C<'.'>

=cut

sub b64digest {
    my $self = shift;

    return en_base64($self->_digest);
}



=head2 reset

    $bcrypt->reset;

Resets the object to the same internal state it was in when it was constructed.

=cut

sub reset {
    my $self = shift;

    delete $self->{_buffer};
    delete $self->{cost};
    delete $self->{salt};

    return $self->new;
}

=head2 salt

    $bcrypt->salt($salt);

Sets the value to be used as a salt. Bcrypt requires B<exactly> 16 octets of salt

It is recommenced that you use a module like L<Data::Entropy::Algorithms> to
provide a truly randomised salt.

When called with no arguments, will return the whatever is the current salt

=cut

sub salt {
    my ($self, $salt) = @_;

    if (defined $salt) {        
        use bytes;
        if (length $salt != 16) {
            croak "Salt must be exactly 16 octets long";
        }

        $self->{salt} = $salt;
        return $self;
    }

    return $self->{salt};
}

=head2 cost

    $bcrypt->cost($cost);

An integer in the range C<'1'..'31'>, this is required.

See L<Crypt::Eksblowfish::Bcrypt> for a detailed description of C<cost>
in the context of the bcrypt algorithm.

When called with no arguments, will return the current cost

=cut

sub cost {
    my ($self, $cost) = @_;
    
    if (defined $cost) {
        # bcrypt requires 2 digit costs, it dies if it's a single digit.
        $cost = sprintf("%02d", $cost);

        if ($cost < 1 || $cost > 31) {
            croak "Cost must be an integer between 1 and 31";
        }

        $self->{cost} = $cost;
        return $self;
    }

    return $self->{cost};
}


# Returns the raw bcrypt digest and resets the object
sub _digest {
    my $self = shift;

    if ($self->cost < 1 || $self->cost > 31) {
        croak "Cost must be an integer between 1 and 31";
    }

    if (!$self->salt) {
        croak "Salt must be specified";
    }

    my $hash = bcrypt_hash({
        key_nul => 1,
        cost    => $self->cost,
        salt    => $self->salt,
    }, $self->{_buffer});

    $self->reset;

    return $hash;
}

1;


=head1 SEE ALSO

L<Digest>, L<Crypt::Eksblowfish::Bcrypt>


=head1 AUTHOR

James Aitken <jaitken@cpan.org>


=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by James Aitken.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
