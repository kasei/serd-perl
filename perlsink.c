/*
 Copyright 2012 Gregory Todd Williams <http://kasei.us/>
 
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
#include "serd_internal.h"

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
	char* l		= NULL;
	char* d		= NULL;
	char* str	= NULL;
	SV* n		= NULL;
	int prefix_len;
	int suffix_len;
	SerdChunk uri_prefix;
	SerdChunk uri_suffix;
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
			strncpy( buf, uri_prefix.buf, uri_prefix.len);
			buf[ uri_prefix.len ]	= '\0';
			strncat( buf, uri_suffix.buf, uri_suffix.len);
			n = S_new_node_instance(aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Resource")), 1, sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1)));
			break;
		case SERD_URI:
			buf	= alloca(node->n_bytes+1);
			S_copy_value_to_buffer( buf, node );
			n = S_new_node_instance(aTHX_ sv_2mortal(newSVpvs("RDF::Trine::Node::Resource")), 1, sv_2mortal(newSVpvn_utf8(buf, strlen(buf), 1)));
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

static bool
write_text(serdperl_sink* handle, TextContext ctx,
           const uint8_t* utf8, size_t n_bytes, uint8_t terminator)
{
	char escape[11] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	for (size_t i = 0; i < n_bytes;) {
		// Fast bulk write for long strings of printable ASCII
		size_t j = i;
		for (; j < n_bytes; ++j) {
			if (utf8[j] == terminator || utf8[j] == '\\' || utf8[j] == '"'
			    || (!in_range(utf8[j], 0x20, 0x7E))) {
				break;
			}
		}

		if (j > i) {
			fwrite(&utf8[i], j-i, 1, stdout);
			i = j;
			continue;
		}

		uint8_t in = utf8[i++];
		if (ctx == WRITE_LONG_STRING) {
			if (in == '\\') {
				fprintf(stdout, "\\\\"); continue;
			} else if (in == '\"' && i == n_bytes) {
				fprintf(stdout, "\\\""); continue;  // '"' at end of string
			}
		} else {
			switch (in) {
			case '\\': fprintf(stdout, "\\\\"); continue;
			case '\n': fprintf(stdout, "\\n");  continue;
			case '\r': fprintf(stdout, "\\r");  continue;
			case '\t': fprintf(stdout, "\\t");  continue;
			case '"':
				if (terminator == '"') {
					fprintf(stdout, "\\\"");
					continue;
				}  // else fall-through
			default: break;
			}

			if (in == terminator) {
				snprintf(escape, sizeof(escape), "\\u%04X", terminator);
				fwrite(escape, 6, 1, stdout);
				continue;
			}
		}

		uint32_t c    = 0;
		size_t   size = 0;
		if ((in & 0x80) == 0) {  // Starts with `0'
			c = in & 0x7F;
			if (in_range(c, 0x20, 0x7E)
			    || (is_space(c) && ctx == WRITE_LONG_STRING)) {
			    fwrite(&in, 1, 1, stdout); // Print ASCII character
			} else {
				snprintf(escape, sizeof(escape), "\\u%04X", c);
				fwrite(escape, 6, 1, stdout); // Escape ASCII control character
			}
			continue;
		} else if ((in & 0xE0) == 0xC0) {  // Starts with `110'
			size = 2;
			c    = in & 0x1F;
		} else if ((in & 0xF0) == 0xE0) {  // Starts with `1110'
			size = 3;
			c    = in & 0x0F;
		} else if ((in & 0xF8) == 0xF0) {  // Starts with `11110'
			size = 4;
			c    = in & 0x07;
		} else {
			fprintf(stderr, "Invalid UTF-8: %X\n", in);
			const uint8_t replacement_char[] = { 0xEF, 0xBF, 0xBD };
			fwrite(replacement_char, sizeof(replacement_char), 1, stdout);
			return false;
		}

#define READ_BYTE() \
		in = utf8[i++] & 0x3f; \
		c  = (c << 6) | in;

		switch (size) {
		case 4: READ_BYTE();
		case 3: READ_BYTE();
		case 2: READ_BYTE();
		}

		if (c < 0xFFFF) {
			snprintf(escape, sizeof(escape), "\\u%04X", c);
			fwrite(escape, 6, 1, stdout);
		} else {
			snprintf(escape, sizeof(escape), "\\U%08X", c);
			fwrite(escape, 10, 1, stdout);
		}
	}
	return true;
}

static size_t file_sink (const void* buf, size_t len, void* stream) {
	return fwrite(buf, len, 1, stream);
}

static bool
write_node(serdperl_sink*	handle,
           const SerdNode*	node,
           const SerdNode*	datatype,
           const SerdNode*	lang,
           Field			field,
           SerdStatementFlags flags)
{
	SerdChunk uri_prefix;
	SerdChunk uri_suffix;
	SerdURI uri;
	switch (node->type) {
		case SERD_BLANK:
		   fprintf(stdout, "_:");
			fwrite(node->buf, node->n_bytes, 1, stdout);
			break;
		case SERD_CURIE:
			if (serd_env_expand(handle->env, node, &uri_prefix, &uri_suffix)) {
				fprintf(stderr, "Undefined namespace prefix `%s'\n", node->buf);
				return false;
			}
			fprintf(stdout, "<");
			write_text(handle, WRITE_URI, uri_prefix.buf, uri_prefix.len, '>');
			write_text(handle, WRITE_URI, uri_suffix.buf, uri_suffix.len, '>');
			fprintf(stdout, ">");
			break;
		case SERD_LITERAL:
			fprintf(stdout, "\"");
			write_text(handle, WRITE_STRING, node->buf, node->n_bytes, '"');
			fprintf(stdout, "\"");
			if (lang && lang->buf) {
				fprintf(stdout, "@");
				fwrite(lang->buf, lang->n_bytes, 1, stdout);
			} else if (datatype && datatype->buf) {
				fprintf(stdout, "^^");
				write_node(handle, datatype, NULL, NULL, FIELD_NONE, flags);
			}
			break;
		case SERD_URI:
			serd_uri_parse(node->buf, &uri);
			SerdURI abs_uri;
			serd_uri_resolve(&uri, &handle->base_uri, &abs_uri);
			fprintf(stdout, "<");
			serd_uri_serialise(&abs_uri, file_sink, stdout);
			fprintf(stdout, ">");
//			fprintf(stdout, "<");
//			write_text(handle, WRITE_URI, node->buf, node->n_bytes, '>');
//			fprintf(stdout, ">");
		default:
			break;
	}
	return true;
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
	
	/*
	fprintf(stdout, "%s: ", handle->prefix);
	write_node(handle, subject, NULL, NULL, FIELD_SUBJECT, flags);
	fprintf(stdout, " ");
	write_node(handle, predicate, NULL, NULL, FIELD_PREDICATE, flags);
	fprintf(stdout, " ");
	if (!write_node(handle, object, datatype, lang, FIELD_OBJECT, flags)) {
		return SERD_ERR_UNKNOWN;
	}
	fprintf(stdout, " .\n");
	*/
	return SERD_SUCCESS;
}

SerdStatus perlsink_set_prefix(serdperl_sink* handle, const SerdNode* name, const SerdNode* uri) {
	serd_env_set_prefix(handle->env, name, uri);
	return SERD_SUCCESS;
}

SerdStatus perlsink_set_base_uri(serdperl_sink* handle, const SerdNode* uri) {
	if (!serd_env_set_base_uri(handle->env, uri)) {
		serd_env_get_base_uri(handle->env, &handle->base_uri);
		return SERD_SUCCESS;
	}
	return SERD_ERR_UNKNOWN;
}

serdperl_sink* new_perlsink ( const SerdURI* base_uri ) {
	serdperl_sink* p	= malloc(sizeof(serdperl_sink));
	p->env		= serd_env_new(base_uri);
	p->callback	= NULL;
	p->base_uri	= base_uri ? *base_uri : SERD_URI_NULL;
	return p;
}

void free_perlsink ( serdperl_sink* p ) {
	serd_env_free(p->env);
	free(p);
}
