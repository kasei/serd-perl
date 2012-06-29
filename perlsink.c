/*
  Copyright 2012 Gregory Todd Williams <gwilliams@cpan.org>

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
*/

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
//#include "ppport.h"
#include "perlsink.h"
#include "serd.h"

typedef enum {
	FIELD_NONE,
	FIELD_SUBJECT,
	FIELD_PREDICATE,
	FIELD_OBJECT
} Field;

typedef enum {
	WRITE_URI,
	WRITE_STRING,
	WRITE_LONG_STRING
} TextContext;


static void
S_copy_value_to_buffer ( char* buf, const SerdNode* node ) {
	buf[ node->n_bytes ]	= '\0';
	memcpy(buf, node->buf, node->n_bytes);
	return;
}

static SV*
S_new_node_instance (pTHX_ SV *klass, UV n_args, ...) {
  int count;
  va_list ap;
  SV *ret;
  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  EXTEND(SP, n_args + 1);
  PUSHs(klass);
  va_start(ap, n_args);
  while (n_args--)
    PUSHs(va_arg(ap, SV *));
  va_end(ap);
  PUTBACK;
  count = call_method("new", G_SCALAR);
  if (count != 1)
    croak("Big trouble");
  SPAGAIN;
  ret = POPs;
  SvREFCNT_inc(ret);
  FREETMPS;
  LEAVE;

  return ret;
}


static SV*
S_canonical_literal_value (pTHX_ SV* value, SV* datatype) {
	int count;
	SV *ret;
	SV* class	= sv_2mortal(newSVpvs("RDF::Trine::Node::Literal"));
	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	EXTEND(SP,4);
	PUSHs(class);
	PUSHs(value);
	PUSHs(datatype);
	PUSHs(sv_2mortal(newSViv(1)));
	PUTBACK;
	count	= call_method("canonicalize_literal_value", G_SCALAR);
	if (count != 1)
		croak("Big trouble");
	SPAGAIN;
	ret	= POPs;
	SvREFCNT_inc(ret);
	FREETMPS;
	LEAVE;
	return ret;
}

SV*
S_serd_node_to_object (serdperl_sink* handle, const SerdNode* node, const SerdNode* dt, const SerdNode* lang) {
	char* buf	= NULL;
	char* buf2	= NULL;
	char* l		= NULL;
	char* d		= NULL;
	char* str	= NULL;
	SV* n		= NULL;
	int prefix_len;
	int suffix_len;
	SerdURI uri;
	SerdChunk uri_prefix;
	SerdChunk uri_suffix;
	const SerdNode* base;

	base	= serd_env_get_base_uri(handle->env, &uri);
	buf2	= alloca(base->n_bytes+1);
	S_copy_value_to_buffer( buf2, base );

	switch (node->type) {
		case SERD_BLANK:
			buf	= alloca(node->n_bytes+1);
			S_copy_value_to_buffer( buf, node );
			n = S_new_node_instance(aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Blank")), 1,
				sv_2mortal(newSVpv(buf, 0)));
			break;
		case SERD_CURIE:
			if (serd_env_expand(handle->env, node, &uri_prefix, &uri_suffix)) {
				fprintf(stderr, "Undefined namespace prefix `%s'\n", node->buf);
				return false;
			}
			buf	= alloca(uri_prefix.len+uri_suffix.len+1);
			strncpy( buf, (const char *) uri_prefix.buf, uri_prefix.len);
			buf[ uri_prefix.len ]	= '\0';
			strncat( buf, (const char *) uri_suffix.buf, uri_suffix.len);
			
			if (base->n_bytes > 0) {
				n = S_new_node_instance(
					aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Resource")),
					2,
					sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1)),
					sv_2mortal(newSVpvn_utf8(buf2, strlen(buf2), 1))
				);
			} else {
				n = S_new_node_instance(
					aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Resource")),
					1,
					sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1))
				);
			}
			break;
		case SERD_URI:
			buf	= alloca(node->n_bytes+1);
			S_copy_value_to_buffer( buf, node );
			if (base->n_bytes > 0) {
				n = S_new_node_instance(
					aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Resource")),
					2,
					sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1)),
					sv_2mortal(newSVpvn_utf8(buf2, strlen(buf2), 1))
				);
			} else {
				n = S_new_node_instance(
					aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Resource")),
					1,
					sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1))
				);
			}
			break;
		case SERD_LITERAL:
			buf	= alloca(node->n_bytes+1);
			S_copy_value_to_buffer( buf, node );
			if (lang && lang->buf) {
				l	= alloca(lang->n_bytes+1);
				S_copy_value_to_buffer( l, lang );
				n = S_new_node_instance(aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Literal")), 2,
					sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1)),
					sv_2mortal(newSVpv(l, 0))
					);
			} else if (dt && dt->buf) {
				d	= alloca(dt->n_bytes+1);
				S_copy_value_to_buffer( d, dt );
				SV* value	= S_canonical_literal_value( aTHX_
								sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1)),
								sv_2mortal(newSVpvn_utf8(d, strlen(d), 1))
							);
				n = S_new_node_instance(aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Literal")), 3,
					sv_2mortal(value),
					&PL_sv_undef,
					sv_2mortal(newSVpvn_utf8(d, strlen(d), 1))
					);
			} else {
				n = S_new_node_instance(aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Literal")), 1,
					sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1))
					);
			}
			break;
		default:
			break;
	}
	return sv_2mortal(n);
}

SerdStatus perlsink_write_statement(serdperl_sink* handle, SerdStatementFlags flags, const SerdNode* graph, const SerdNode* subject, const SerdNode* predicate, const SerdNode* object, const SerdNode* datatype, const SerdNode* lang) {
	if (handle->callback) {
		dSP;
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		
		SV* s	= S_serd_node_to_object(handle, subject, NULL, NULL);
		SV* p	= S_serd_node_to_object(handle, predicate, NULL, NULL);
		SV* o	= S_serd_node_to_object(handle, object, datatype, lang);
		SV* st	= S_new_node_instance(aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Statement")), 3, s, p, o);
		
		XPUSHs(sv_2mortal(st));
		PUTBACK;
		call_sv( handle->callback, G_VOID|G_DISCARD );
		FREETMPS;
		LEAVE;
	}
	return SERD_SUCCESS;
}

SerdStatus perlsink_set_prefix(serdperl_sink* handle, const SerdNode* name, const SerdNode* uri) {
	serd_env_set_prefix(handle->env, name, uri);
	return SERD_SUCCESS;
}

SerdStatus perlsink_set_base_uri(serdperl_sink* handle, const SerdNode* uri) {
	if (!serd_env_set_base_uri(handle->env, uri)) {
		SerdURI base;
		serd_env_get_base_uri(handle->env, &base);
		return SERD_SUCCESS;
	}
	return SERD_ERR_UNKNOWN;
}

serdperl_sink* new_perlsink ( const char* base_uri ) {
	serdperl_sink* p	= malloc(sizeof(serdperl_sink));
	p->callback	= NULL;
	p->error	= NULL;
	p->base_uri	= NULL;
	
	SerdNode base	= SERD_NODE_NULL;
	if (base_uri) {
		SerdURI out;
		p->base_uri	= malloc(strlen(base_uri)+1);
		strcpy(p->base_uri, base_uri);
		base		= serd_node_new_uri_from_string((const uint8_t*) base_uri, NULL, &out);
		serd_node_free(&base);
	}
	p->env		= serd_env_new(&base);
	return p;
}

void free_perlsink ( serdperl_sink* p ) {
	if (p->base_uri) {
		free(p->base_uri);
	}
	serd_env_free(p->env);
	if (p->error) {
		SvREFCNT_dec(p->error);
		p->error	= NULL;
	}
	free(p);
}

int perlsink_error_sink (serdperl_sink* handle, const uint8_t* filename, unsigned line, unsigned col, const char* fmt, va_list args) {
	if (handle->error) {
		SvREFCNT_dec(handle->error);
		handle->error	= NULL;
	}
	
	handle->error	= newSVpvf("Parser error: %s:%u:%u: ", filename, line, col);
	sv_vcatpvfn(handle->error, fmt, strlen(fmt), args, NULL, 0, NULL);
//	fprintf(stderr, "perl error: %s:%u:%u: ", filename, line, col);
//	vfprintf(stderr, fmt, args);
	return 0;
}
