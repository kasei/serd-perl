use strict;
use warnings;
use ExtUtils::MakeMaker;
use ExtUtils::Depends;
use ExtUtils::PkgConfig;
use Data::Dumper;

my $deps = ExtUtils::Depends->new('FourStore', 'XS::Object::Magic');
# $deps->set_inc($fourstore{cflags});
# $deps->set_libs($fourstore{libs});

my $inc_files = join(' ', glob '*.h');
my $src_files = join(' ', glob '*.c');
my $xs_files  = join(' ', glob '*.xs');

my %WriteMakefileArgs	= (
	NAME => 'RDF::Trine::Parser::Serd',
	VERSION_FROM => 'lib/RDF/Trine/Parser/Serd.pm',
	$deps->get_makefile_vars,
	OBJECT => 'Serd$(OBJ_EXT) env$(OBJ_EXT) node$(OBJ_EXT) perlsink$(OBJ_EXT) reader$(OBJ_EXT) string$(OBJ_EXT) uri$(OBJ_EXT) writer$(OBJ_EXT)',
	depend	=> { 'Serd.c' => "$inc_files $src_files $xs_files" },
);

warn Dumper($WriteMakefileArgs{depend});

$WriteMakefileArgs{CCFLAGS} = ( $Config::Config{ccflags} || '' ) . ' -I. -std=gnu99';

WriteMakefile( %WriteMakefileArgs );
