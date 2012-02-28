use strict;
use warnings;
use ExtUtils::MakeMaker;
use ExtUtils::Depends;
use ExtUtils::PkgConfig;

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
	OBJECT => 'serdperl$(OBJ_EXT) serd$(OBJ_EXT) perlsink$(OBJ_EXT)',
	depend	=> { 'serdperl.c' => "$inc_files $src_files $xs_files" },
);

$WriteMakefileArgs{CCFLAGS} = ( $Config::Config{ccflags} || '' ) . ' -I. -std=gnu99';

WriteMakefile( %WriteMakefileArgs );
