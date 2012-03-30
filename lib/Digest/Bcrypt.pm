package Digest::Bcrypt;

# ABSTRACT: Perl interface to the bcrypt algorithm

=head1 NAME

Digest::Bcrypt - Perl interface to the bcrypt algorithm

=head1 SYNOPSIS

=head1 USAGE

    use Digest::Bcrypt;
 
    my $ctx = Digest::Bcrypt->new;

    # $cost is an integer between 1 and 31
    $ctx->cost($cost);

    # $salt must be exactly 16 octets long
    $ctx->salt($salt);

    $ctx->add($data);

    $digest = $ctx->digest;
    $digest = $ctx->hexdigest;

    # Note bcrypt uses a non-standard base64 dictionary
    # that replaces + with .
    $digest = $ctx->b64digest;

=cut

use strict;

use parent 'Digest::base';

use Carp qw(croak);
use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash en_base64);

our $VERSION = '0.1.0';


sub new {
    my $class = shift;

    return bless {
        _buffer => '',
    }, ref($class) || $class;
}

sub reset {
    my $self = shift;

    delete $self->{_buffer};
    delete $self->{cost};
    delete $self->{salt};

    return $self->new;
}


sub clone {
    my $self = shift;

    return bless {
        cost    => $self->cost,
        salt    => $self->salt,
        _buffer => $self->{_buffer},
    }, ref($self);
}


sub add {
    my $self = shift;

    $self->{_buffer} .= join('', @_);

    return $self;
}


sub digest {
    my $self = shift;

    return $self->_digest;
}



# Note bcrypt doesn't use the standard base64 alphabet
# '+' is replaced with '.' - there is no padding.
sub b64digest {
    my $self = shift;

    return en_base64($self->_digest);
}



# Getter / setter for setting EXACTLY 16 octets of salt
sub salt {
    my ($self, $salt) = @_;

    if ($salt) {        
        use bytes;
        if (length $salt != 16) {
            croak "Salt must be exactly 16 octets long";
        }

        $self->{salt} = $salt;
        return $self;
    }

    return $self->{salt};
}


# Getter / setter for setting the cost / work factor
sub cost {
    my ($self, $cost) = @_;

    if ($cost) {
        if ($cost !~ /^\d+$/ || $cost > 31 || $cost < 1) {
            croak "Cost must be an integer between 1 and 31";
        }

        $self->{cost} = sprintf("%02d", $cost);;
        return $self;
    }

    return $self->{cost};
}


# Returns the raw bcrypt digest and resets the object
sub _digest {
    my $self = shift;

    my $hash = bcrypt_hash({
        key_nul => 1,
        cost    => $self->cost,
        salt    => $self->salt,
    }, $self->{_buffer});
    
    $self->reset;

    return $hash;
}



1;