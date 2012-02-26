use strict;
use warnings;
use ExtUtils::MakeMaker;
use ExtUtils::Depends;
use ExtUtils::PkgConfig;
use Data::Dumper;

my $deps = ExtUtils::Depends->new('FourStore', 'XS::Object::Magic');
# $deps->set_inc($fourstore{cflags});
# $deps->set_libs($fourstore{libs});

warn Dumper({$deps->get_makefile_vars});

my %WriteMakefileArgs	= (
	NAME => 'RDF::Trine::Parser::Serd',
	VERSION_FROM => 'lib/RDF/Trine/Parser/Serd.pm',
	$deps->get_makefile_vars,
	CCFLAGS => '-std=gnu99',
	OBJECT => 'xs/Serd$(OBJ_EXT) src/env$(OBJ_EXT) src/node$(OBJ_EXT) src/perlsink$(OBJ_EXT) src/reader$(OBJ_EXT) src/string$(OBJ_EXT) src/uri$(OBJ_EXT) src/writer$(OBJ_EXT)',
	XS => {
		'xs/Serd.xs' => 'xs/Serd.c',
	},
	PREREQ_PM => {
		'Params::Util'	=> 0,
	},
);

WriteMakefile( %WriteMakefileArgs );
