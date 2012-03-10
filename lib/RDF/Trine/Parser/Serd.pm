=head1 NAME

RDF::Trine::Parser::Serd - RDF Parser based on Serd

=head1 VERSION

This document describes RDF::Trine::Parser::Serd version 0.000_01

=head1 SYNOPSIS

 use RDF::Trine::Parser::Serd;

=head1 DESCRIPTION

RDF::Trine::Parser::Serd provides an implementation of the RDF::Trine::Parser
API based on the Serd RDF parser L<http://drobilla.net/software/serd/>. It will
parse Turtle and N-Triples content.

=cut

package RDF::Trine::Parser::Serd;

use strict;
use warnings;
no warnings 'redefine';
use base qw(RDF::Trine::Parser);

use Data::Dumper;
use Scalar::Util qw(refaddr reftype blessed);
use XSLoader;
use XS::Object::Magic;
use RDF::Trine::Error qw(:try);

######################################################################

our $VERSION;
BEGIN {
	$VERSION	= "0.000_01";
	my $class	= __PACKAGE__;
	$RDF::Trine::Store::STORE_CLASSES{ $class }	= $VERSION;
}

######################################################################

XSLoader::load(__PACKAGE__, $VERSION);

=head1 METHODS

Beyond the methods documented below, this class inherits methods from the
L<RDF::Trine::Store> class.

=over 4

=cut

sub parse {
	my $self	= $_[0];
	unless (defined($_[1])) {
		$_[1]	= "";	# don't pass an undef base uri to the XS
	}
	my $r	= &parse2;
	if ($r != SERD_SUCCESS()) {
		my $error	= $self->error;
		throw RDF::Trine::Error::ParserError -text => $error;
	}
}

sub parse_file {
	my $self	= $_[0];
	unless (defined($_[1])) {
		$_[1]	= "";	# don't pass an undef base uri to the XS
	}
	my $r	= &parse_file2;
	if ($r != SERD_SUCCESS()) {
		my $error	= $self->error;
		throw RDF::Trine::Error::ParserError -text => $error;
	}
}

1;

__END__

=back

=head1 BUGS

Please report any bugs or feature requests to the Perl+RDF mailing list at C<< <dev@perlrdf.org> >>.

=head1 AUTHOR

Gregory Todd Williams  C<< <gwilliams@cpan.org> >>

=head1 COPYRIGHT

Copyright 2012 Gregory Todd Williams

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THIS SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

=cut
