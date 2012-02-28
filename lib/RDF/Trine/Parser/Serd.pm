=head1 NAME

RDF::Trine::Parser::Serd - RDF Parser based on Serd

=head1 VERSION

This document describes RDF::Trine::Parser::Serd version 0.135

=head1 SYNOPSIS

 use RDF::Trine::Parser::Serd;

=head1 DESCRIPTION

RDF::Trine::Parser::Serd provides a RDF::Trine::Parser API to interact with the
Serd API.

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
	$VERSION	= "0.135";
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

Copyright (c) 2012
This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
