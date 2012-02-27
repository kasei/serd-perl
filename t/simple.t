use strict;
use Test::More;
use Data::Dumper;

use_ok( 'RDF::Trine::Parser::Serd' );

{
	my $p	= RDF::Trine::Parser::Serd->new(sub {});
	isa_ok( $p, 'RDF::Trine::Parser::Serd' );
}

{
	my $calls	= 0;
	my $p	= RDF::Trine::Parser::Serd->new(sub { $calls++ });
	$p->parse( 'http://example.org/', "<s> <p> <o> .\n" );
	is( $calls, 1, 'statement handler called 1 time' );
}

{
	my $calls	= 0;
	my $p	= RDF::Trine::Parser::Serd->new(sub { $calls++ });
	$p->parse( 'http://example.org/', "<s> <p> 1,2,3 .\n" );
	is( $calls, 3, 'statement handler called 3 times' );
}

{
	my $calls	= 0;
	my $p	= RDF::Trine::Parser::Serd->new(sub {
		$calls++;
		my $st	= shift;
		isa_ok( $st, 'RDF::Trine::Statement' );
		isa_ok( $st->subject, 'RDF::Trine::Node::Resource' );
		is( $st->subject->uri_value, 'http://example.org/s', 'expected absolute IRI base resolution (API-set base)' );
		isa_ok( $st->predicate, 'RDF::Trine::Node::Resource' );
		is( $st->predicate->uri_value, 'http://example.org/base/p', 'expected relative IRI base resolution (API-set base)' );
	});
	$p->parse( 'http://example.org/base/', "</s> <p> 7 .\n" );
	is( $calls, 1, 'statement handler called 1 time' );
}

{
	my $calls	= 0;
	my $p	= RDF::Trine::Parser::Serd->new(sub {
		$calls++;
		my $st	= shift;
		isa_ok( $st, 'RDF::Trine::Statement' );
		isa_ok( $st->subject, 'RDF::Trine::Node::Resource' );
		is( $st->subject->uri_value, 'http://example.org/s', 'expected absolute IRI base resolution (data-set base)' );
		isa_ok( $st->predicate, 'RDF::Trine::Node::Resource' );
		is( $st->predicate->uri_value, 'http://example.org/base/p', 'expected relative IRI base resolution (data-set base)' );
	});
	$p->parse( undef, "\@base <http://example.org/base/> .\n</s> <p> 7 .\n" );
	is( $calls, 1, 'statement handler called 1 time' );
}

{
	my $calls	= 0;
	my $p	= RDF::Trine::Parser::Serd->new(sub {
		$calls++;
		my $st	= shift;
		isa_ok( $st, 'RDF::Trine::Statement' );
		isa_ok( $st->object, 'RDF::Trine::Node::Literal' );
		ok( $st->object->has_datatype, 'object is a datatyped literal' );
		my $dt	= $st->object->literal_datatype;
		is( $st->object->literal_value, '7', 'expected literal value' );
		is( $dt, 'http://www.w3.org/2001/XMLSchema#integer', 'expected integer datatype' );
	});
	$p->parse( 'http://example.org/', "<s> <p> 7 .\n" );
	is( $calls, 1, 'statement handler called 1 time' );
}

done_testing();
