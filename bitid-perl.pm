package Bitid;

use strict;
use warnings;

use LWP::Simple;
use URI::Encode;
use Data::Dumper;
use Crypt::PK::ECC;
use Encode::Base58::GMP;
use Digest::SHA qw( sha256_hex );
use Math::Random::Secure qw( irand );

use constant QR_GEN => "https://chart.googleapis.com/chart?cht=qr&chs=300x300&chl=";
use constant SCHEME => 'bitid';

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


}

sub new {

 my ($caller, %arg) = @_;
 my $caller_is_obj = ref($caller);
 my $class = $caller_is_obj || $caller;
 my $self = bless {}, $class;

 $self->{_pk} = Crypt::PK::ECC->new();
 $self->{_uri_encode} = URI::Encode->new( );
 

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
 my $address = shift;
 my $addr_dec = decode_base58($address, 'bitcoin');
 my $checksum = substr($addr_dec, -4);
print "$addr_dec\n";
 $addr_dec = substr($addr_dec, 0, -4);

my $redo = sha256_hex( sha256_hex($addr_dec) );
 my $expCheckSum = substr( sha256_hex( sha256_hex($addr_dec) ), 0, 4);
 print "$checksum, $expCheckSum\n";
 print "$addr_dec\n";
 print "$redo\n";
 
 return ($expCheckSum eq $checksum) ? 1 : 0;
}


sub destroy {

}

