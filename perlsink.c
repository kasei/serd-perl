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
write_node(serdperl_sink*		  handle,
           const SerdNode*    node,
           const SerdNode*    datatype,
           const SerdNode*    lang,
           Field              field,
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
	fprintf(stdout, "%s: ", handle->prefix);
	write_node(handle, subject, NULL, NULL, FIELD_SUBJECT, flags);
	fprintf(stdout, " ");
	write_node(handle, predicate, NULL, NULL, FIELD_PREDICATE, flags);
	fprintf(stdout, " ");
	if (!write_node(handle, object, datatype, lang, FIELD_OBJECT, flags)) {
		return SERD_ERR_UNKNOWN;
	}
	fprintf(stdout, " .\n");
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

serdperl_sink* new_perlsink ( const SerdURI* base_uri, const char* prefix ) {
	serdperl_sink* p	= malloc(sizeof(serdperl_sink));
	p->env		= serd_env_new(&base_uri);
	p->prefix	= prefix;
	p->base_uri    = base_uri ? *base_uri : SERD_URI_NULL;
	return p;
}

void free_perlsink ( serdperl_sink* p ) {
	serd_env_free(p->env);
	free(p);
}
