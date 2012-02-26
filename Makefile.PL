use ExtUtils::MakeMaker;
use ExtUtils::Depends;
use ExtUtils::PkgConfig;

my $deps = ExtUtils::Depends->new('FourStore', 'XS::Object::Magic');
# $deps->set_inc($fourstore{cflags});
# $deps->set_libs($fourstore{libs});

WriteMakefile(
    NAME => 'RDF::Trine::Parser::Serd',
    VERSION_FROM => 'lib/RDF/Trine/Parser/Serd.pm',
    $deps->get_makefile_vars,
    PREREQ_PM => {
    	'Params::Util'	=> 0,
    },
);
