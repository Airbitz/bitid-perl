package BitID;

use strict;
use warnings;

use LWP::Simple;
use URI::Encode;
use Data::Dumper;
use MIME::Base64;
use Crypt::PK::ECC;
use Digest::SHA qw( sha256 );
use Math::BigInt lib => 'GMP';
use Math::Random::Secure qw( irand );

use constant QR_GEN => "https://chart.googleapis.com/chart?cht=qr&chs=300x300&chl=";
use constant SCHEME => 'bitid';

#use Encode::Base58::GMP;

# this script has been ported from here
# https://github.com/conejoninja/bitid-php/blob/master/BitID.php

{

   sub _construct {
       my $self = shift;
       $self->{_secp256k1} = $self->{_pk}->generate_key({
           curve_name => 'secp256k1',
           prime => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
           A => 0,
           B => 7,
           Gx => '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
           Gy => '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
           order => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
           cofactor => 1,
       });

    }

    # TODO, possible difference between php and perl pack
    sub _numToVarIntString {
        my $self = shift;
        my $i    = shift;
        if ($i < 0xfd) {
            return chr($i);
        } elsif ($i <= 0xffff) {
            return pack('Cv', 0xfd, $i);
        } elsif ($i <= 0xffffffff) {
            return pack('CV', 0xfe, $i);
        } else {
            die 'int too large';
        }
    }

    sub _bin2gmp($binStr) {
        my $self  = shift;
        my $binStr = shift;
        my $v = Math::BigInt->bzero();;
        for (my $i = 0; $i < strlen($binStr); $i++) {
            $v = $v->badd($v->bmul($v, 256), ord(substr($binStr, $i, 1)));
        }
        return $v;
    }

    sub _recoverPubKey {
        my $self = shift;
        my %args = @_;

        my $isYEven = 0;
        $isYEven = 1 if ($args{recoveryFlags & 1) != 0);
        
        my $isSecondKey = 0;
        $isSecondKey = 1 if ($args{recoveryFlags & 2) != 0);

        my $curve = $self->{_secp256k1};
        #my $signature = new Signature($args{r}, $args{s});

    }


}


sub new {

    my ($caller, %arg) = @_;
    my $caller_is_obj = ref($caller);
    my $class = $caller_is_obj || $caller;
    my $self = bless {}, $class;
   
    $self->{_pk} = Crypt::PK::ECC->new();
    $self->{_uri_encode} = URI::Encode->new( );
    foreach my $key (keys %arg) {
        $self->{"_$key"} = $arg{$key};
    }
    

    return $self;
}

sub generateNonce {
    my $self = shift;
    return join'', map +(0..9,'a'..'z','A'..'Z')[irand(10+26*2)], 1..(shift||16);
    return irand(9 x (shift||16));
}
# bitid uri: bitid:www.site.com/callback?x=bOLhlqGxv3UHK805
sub extractNonce {
    my $self = shift;
    my $uri = shift;
    $uri =~ m/.*(\?x=)([\w]{16})/;
    return $2;
}


sub qrCode {
    my $self = shift;
    my $uri = shift;
    
    my $encodedURI = $self->{_uri_encode}->encode($uri);
    my $qrCode = get( QR_GEN.$encodedURI );
    die "Unable to fetch qrcode from :".QR_GEN.$encodedURI unless ($qrCode); 
    return $qrCode;
}

sub buildURI {
    my $self = shift;
    my $callback = shift;
    my $nonce = shift||$self->generateNonce();
   
    my $secure = '';
    $secure = '&u=1' if ($callback =~ /^https/);
    $callback =~ s!^http(s)?://!!; 

    return SCHEME . "://$callback?x=${nonce}${secure}";
}

sub isAddressValid {
    my $self = shift;
    my $address = shift||$self->{_address};

    # the orig php lib has testnet validation
    if (length($address) != 21 ) {
        return 0;
    }

    my @b58 = qw{
      1 2 3 4 5 6 7 8 9
      A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
      a b c d e f g h i j k   m n o p q r s t u v w x y z
    };
    my %b58 = map { $b58[$_] => $_ } 0 .. 57;
    use integer;
    my @addr;
    for my $c ( map { $b58{$_} } $address =~ /./g ) {
        for (my $j = 25; $j--; ) {
            $c += 58 * ($addr[$j] // 0);
            $addr[$j] = $c % 256;
            $c /= 256;
        }
    }

    my $expChecksum = join('', map { chr } @addr[21..24]); 
    my $checksum = substr sha256(sha256 pack 'C*', @addr[0..20]), 0, 4;
 
    return ($expChecksum eq $checksum) ? 1 : 0;
}

sub isMessageSignatureValid {
    my $self = shift;
    my %args = @_;
   
    die "Need address"   unless defined($args{address});
    die "Need signature" unless defined($args{signature});
    die "Need message"   unless defined($args{message});

    my $signature = decode_base64($signature);
    return 0 unless (length($signature) ==  65);

    my $recoveryFlags = ord( $signature - 27 );
    if ($recoveryFlags < 0 || $recoveryFlags > 7) {
        return 0;
    }
    my $isCompressed = 0;
    $isCompressed = 1 if (($recoveryFlags & 4) != 0);

    #$messageHash = hash('sha256', hash('sha256', "\x18Bitcoin Signed Message:\n" . $this->_numToVarIntString(strlen($message)).$message, true), true);
    my $messageHash = sha256(sha256("\x18Bitcoin Signed Message:\n" . $self->_numToVarIntString(length($message)) . $message));

    # up to here
    #$pubkey = $this->_recoverPubKey($this->_bin2gmp(substr($signature, 1, 32)), $this->_bin2gmp(substr($signature, 33, 32)), $this->_bin2gmp($messageHash), $recoveryFlags, $this->_secp256k1_G);

}


sub destroy {

}

1
