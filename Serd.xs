#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "xs_object_magic.h"
#include "serd_internal.h"
#include "perlsink.h"

static SV *
S_new_instance (pTHX_ HV *klass)
{
  SV *obj, *self;

  obj = (SV *)newHV();
  self = newRV_noinc(obj);
  sv_bless(self, klass);

  return self;
}

static SV *
S_attach_struct (pTHX_ SV *obj, void *ptr)
{
  xs_object_magic_attach_struct(aTHX_ SvRV(obj), ptr);
  return obj;
}

#define new_instance(klass)  S_new_instance(aTHX_ klass)
#define attach_struct(obj, ptr)  S_attach_struct(aTHX_ obj, ptr)

#define EXPORT_FLAG(flag)  newCONSTSUB(stash, #flag, newSVuv(flag))

MODULE = RDF::Trine::Parser::Serd  PACKAGE = RDF::Trine::Parser::Serd  PREFIX = serdperl_

PROTOTYPES: DISABLE

BOOT:
{
  HV *stash = gv_stashpvs("RDF::Trine::Parser::Serd", 0);
  EXPORT_FLAG(SERD_SUCCESS);         /**< No error */
  EXPORT_FLAG(SERD_FAILURE);         /**< Non-fatal failure */
}


void
new (klass, cb)
    SV *klass
    SV *cb
  PREINIT:
    serdperl_sink* handle;
  PPCODE:
    if (!(handle = new_perlsink(NULL, cb))) {
      croak("foo");
    }
	
    XPUSHs(attach_struct(new_instance(gv_stashsv(klass, 0)), handle));

void
DESTROY (serdperl_sink *handle)
    CODE:
      free_perlsink(handle);


void
serdperl_parse_file (handle, base_uri_str, filename)
    serdperl_sink *handle
    const char* base_uri_str
    const char* filename
  PREINIT:
	FILE* in_fd;
	const uint8_t* input;
	SerdURI base_uri;
	SerdNode base_uri_node;
	SerdReader* reader;
	SerdStatus status;
  PPCODE:
	input = serd_uri_to_path((const uint8_t*) filename);
	if (!input || !(in_fd = serd_fopen((const char*)input, "r"))) {
		return;
	}
	base_uri = SERD_URI_NULL;
	base_uri_node = serd_node_new_uri_from_string(base_uri_str, &base_uri, &base_uri);
	reader = serd_reader_new( SERD_TURTLE, handle, NULL, (SerdBaseSink)perlsink_set_base_uri, (SerdPrefixSink)perlsink_set_prefix, (SerdStatementSink)perlsink_write_statement, (SerdEndSink)NULL);
	status = serd_reader_read_file_handle(reader, in_fd, filename);
	serd_reader_free(reader);
	fclose(in_fd);
	serd_node_free(&base_uri_node);
	return;

void
serdperl_parse (handle, base_uri_str, string)
    serdperl_sink *handle
    const char* base_uri_str
    const char* string
  PREINIT:
	SerdURI base_uri;
	SerdNode base_uri_node;
	SerdReader* reader;
	SerdStatus status;
  PPCODE:
	base_uri = SERD_URI_NULL;
	base_uri_node = serd_node_new_uri_from_string(base_uri_str, &base_uri, &base_uri);
	reader = serd_reader_new( SERD_TURTLE, handle, NULL, (SerdBaseSink)perlsink_set_base_uri, (SerdPrefixSink)perlsink_set_prefix, (SerdStatementSink)perlsink_write_statement, (SerdEndSink)NULL);
	status = serd_reader_read_string(reader, string);
	serd_reader_free(reader);
	serd_node_free(&base_uri_node);
	return;
