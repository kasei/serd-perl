use strict;
use Test::More;
use Data::Dumper;
use Devel::Peek;

use_ok( 'RDF::Trine::Parser::Serd' );

{
	my $calls	= 0;
	my $ttl		= <<'END';
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
_:a foaf:name "Bob" . 
END
	my $p	= RDF::Trine::Parser::Serd->new();
	$p->parse( 'http://example.org/', $ttl, sub {
		$calls++;
		my $st	= shift;
		isa_ok( $st, 'RDF::Trine::Statement' );
		my $p	= $st->predicate;
		my $iri	= $p->uri_value;
		is( $iri, 'http://xmlns.com/foaf/0.1/name', 'expected prefix name expansion' );
	});
	is( $calls, 1, 'statement handler called 1 time' );
}

done_testing();
