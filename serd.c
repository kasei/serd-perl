/*
  Copyright 2011-2012 David Robillard <http://drobilla.net>

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

#ifndef SERD_INTERNAL_H
#define SERD_INTERNAL_H

#define _POSIX_C_SOURCE 201112L /* for posix_memalign and posix_fadvise */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "serd.h"
#include "serd_config.h"

#if defined(HAVE_POSIX_FADVISE) && defined(HAVE_FILENO)
#   include <fcntl.h>
#endif

#define SERD_PAGE_SIZE 4096

#ifndef MIN
#    define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef HAVE_FMAX
static inline double
fmax(double a, double b)
{
	return (a < b) ? b : a;
}
#endif

/* File and Buffer Utilities */

static inline FILE*
serd_fopen(const char* path, const char* mode)
{
	FILE* fd = fopen((const char*)path, mode);
	if (!fd) {
		fprintf(stderr, "Error opening file %s (%s)\n", path, strerror(errno));
		return NULL;
	}
#if defined(HAVE_POSIX_FADVISE) && defined(HAVE_FILENO)
	posix_fadvise(fileno(fd), 0, 0, POSIX_FADV_SEQUENTIAL);
#endif
	return fd;
}

static inline void*
serd_bufalloc(size_t size)
{
#ifdef HAVE_POSIX_MEMALIGN
	void* ptr;
	posix_memalign(&ptr, SERD_PAGE_SIZE, size);
	return ptr;
#else
	return malloc(size);
#endif
}

/* Stack */

/** A dynamic stack in memory. */
typedef struct {
	uint8_t* buf;       ///< Stack memory
	size_t   buf_size;  ///< Allocated size of buf (>= size)
	size_t   size;      ///< Conceptual size of stack in buf
} SerdStack;

/** An offset to start the stack at. Note 0 is reserved for NULL. */
#define SERD_STACK_BOTTOM sizeof(void*)

static inline SerdStack
serd_stack_new(size_t size)
{
	SerdStack stack;
	stack.buf       = (uint8_t*)malloc(size);
	stack.buf_size  = size;
	stack.size      = SERD_STACK_BOTTOM;
	return stack;
}

static inline bool
serd_stack_is_empty(SerdStack* stack)
{
	return stack->size <= SERD_STACK_BOTTOM;
}

static inline void
serd_stack_free(SerdStack* stack)
{
	free(stack->buf);
	stack->buf      = NULL;
	stack->buf_size = 0;
	stack->size     = 0;
}

static inline uint8_t*
serd_stack_push(SerdStack* stack, size_t n_bytes)
{
	const size_t new_size = stack->size + n_bytes;
	if (stack->buf_size < new_size) {
		stack->buf_size *= 2;
		stack->buf = (uint8_t*)realloc(stack->buf, stack->buf_size);
	}
	uint8_t* const ret = (stack->buf + stack->size);
	stack->size = new_size;
	return ret;
}

static inline void
serd_stack_pop(SerdStack* stack, size_t n_bytes)
{
	assert(stack->size >= n_bytes);
	stack->size -= n_bytes;
}

/* Bulk Sink */

typedef struct SerdBulkSinkImpl {
	SerdSink sink;
	void*    stream;
	uint8_t* buf;
	size_t   size;
	size_t   block_size;
} SerdBulkSink;

static inline SerdBulkSink
serd_bulk_sink_new(SerdSink sink, void* stream, size_t block_size)
{
	SerdBulkSink bsink;
	bsink.sink       = sink;
	bsink.stream     = stream;
	bsink.size       = 0;
	bsink.block_size = block_size;
	bsink.buf        = (uint8_t*)serd_bufalloc(block_size);
	return bsink;
}

static inline void
serd_bulk_sink_flush(SerdBulkSink* bsink)
{
	if (bsink->size > 0) {
		bsink->sink(bsink->buf, bsink->size, bsink->stream);
	}
	bsink->size = 0;
}

static inline void
serd_bulk_sink_free(SerdBulkSink* bsink)
{
	serd_bulk_sink_flush(bsink);
	free(bsink->buf);
	bsink->buf = NULL;
}

static inline size_t
serd_bulk_sink_write(const void* buf, size_t len, SerdBulkSink* bsink)
{
	const size_t orig_len = len;
	while (len) {
		const size_t space = bsink->block_size - bsink->size;
		const size_t n     = MIN(space, len);

		// Write as much as possible into the remaining buffer space
		memcpy(bsink->buf + bsink->size, buf, n);
		bsink->size += n;
		buf          = (uint8_t*)buf + n;
		len         -= n;

		// Flush page if buffer is full
		if (bsink->size == bsink->block_size) {
			bsink->sink(bsink->buf, bsink->block_size, bsink->stream);
			bsink->size = 0;
		}
	}
	return orig_len;
}

/* Character utilities */

/** Return true if @a c lies within [min...max] (inclusive) */
static inline bool
in_range(const uint8_t c, const uint8_t min, const uint8_t max)
{
	return (c >= min && c <= max);
}

/** RFC2234: ALPHA := %x41-5A / %x61-7A  ; A-Z / a-z */
static inline bool
is_alpha(const uint8_t c)
{
	return in_range(c, 'A', 'Z') || in_range(c, 'a', 'z');
}

/** RFC2234: DIGIT ::= %x30-39  ; 0-9 */
static inline bool
is_digit(const uint8_t c)
{
	return in_range(c, '0', '9');
}

static inline bool
is_space(const char c)
{
	switch (c) {
	case ' ': case '\f': case '\n': case '\r': case '\t': case '\v':
		return true;
	default:
		return false;
	}
}

static inline bool
is_base64(const uint8_t c)
{
	return is_alpha(c) || is_digit(c) || c == '+' || c == '/' || c == '=';
}

#endif  // SERD_INTERNAL_H

/**
   @file src/env.c
*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	SerdNode name;
	SerdNode uri;
} SerdPrefix;

struct SerdEnvImpl {
	SerdPrefix* prefixes;
	size_t      n_prefixes;
	SerdNode    base_uri_node;
	SerdURI     base_uri;
};

SERD_API
SerdEnv*
serd_env_new(const SerdNode* base_uri)
{
	SerdEnv* env = (SerdEnv*)malloc(sizeof(struct SerdEnvImpl));
	env->prefixes      = NULL;
	env->n_prefixes    = 0;
	env->base_uri_node = SERD_NODE_NULL;
	env->base_uri      = SERD_URI_NULL;
	if (base_uri) {
		serd_env_set_base_uri(env, base_uri);
	}
	return env;
}

SERD_API
void
serd_env_free(SerdEnv* env)
{
	for (size_t i = 0; i < env->n_prefixes; ++i) {
		serd_node_free(&env->prefixes[i].name);
		serd_node_free(&env->prefixes[i].uri);
	}
	free(env->prefixes);
	serd_node_free(&env->base_uri_node);
	free(env);
}

SERD_API
const SerdNode*
serd_env_get_base_uri(const SerdEnv* env,
                      SerdURI*       out)
{
	*out = env->base_uri;
	return &env->base_uri_node;
}

SERD_API
SerdStatus
serd_env_set_base_uri(SerdEnv*        env,
                      const SerdNode* uri_node)
{
	// Resolve base URI and create a new node and URI for it
	SerdURI  base_uri;
	SerdNode base_uri_node = serd_node_new_uri_from_node(
		uri_node, &env->base_uri, &base_uri);

	if (base_uri_node.buf) {
		// Replace the current base URI
		serd_node_free(&env->base_uri_node);
		env->base_uri_node = base_uri_node;
		env->base_uri      = base_uri;
		return SERD_SUCCESS;
	}
	return SERD_ERR_BAD_ARG;
}

static inline SerdPrefix*
serd_env_find(const SerdEnv* env,
              const uint8_t* name,
              size_t         name_len)
{
	for (size_t i = 0; i < env->n_prefixes; ++i) {
		const SerdNode* const prefix_name = &env->prefixes[i].name;
		if (prefix_name->n_bytes == name_len) {
			if (!memcmp(prefix_name->buf, name, name_len)) {
				return &env->prefixes[i];
			}
		}
	}
	return NULL;
}

static void
serd_env_add(SerdEnv*        env,
             const SerdNode* name,
             const SerdNode* uri)
{
	SerdPrefix* const prefix = serd_env_find(env, name->buf, name->n_bytes);
	if (prefix) {
		SerdNode old_prefix_uri = prefix->uri;
		prefix->uri = serd_node_copy(uri);
		serd_node_free(&old_prefix_uri);
	} else {
		env->prefixes = (SerdPrefix*)realloc(
			env->prefixes, (++env->n_prefixes) * sizeof(SerdPrefix));
		env->prefixes[env->n_prefixes - 1].name = serd_node_copy(name);
		env->prefixes[env->n_prefixes - 1].uri  = serd_node_copy(uri);
	}
}

SERD_API
SerdStatus
serd_env_set_prefix(SerdEnv*        env,
                    const SerdNode* name,
                    const SerdNode* uri_node)
{
	if (!name->buf || uri_node->type != SERD_URI) {
		return SERD_ERR_BAD_ARG;
	} else if (serd_uri_string_has_scheme(uri_node->buf)) {
		// Set prefix to absolute URI
		serd_env_add(env, name, uri_node);
	} else {
		// Resolve relative URI and create a new node and URI for it
		SerdURI  abs_uri;
		SerdNode abs_uri_node = serd_node_new_uri_from_node(
			uri_node, &env->base_uri, &abs_uri);

		// Set prefix to resolved (absolute) URI
		serd_env_add(env, name, &abs_uri_node);
		serd_node_free(&abs_uri_node);
	}
	return SERD_SUCCESS;
}

SERD_API
SerdStatus
serd_env_set_prefix_from_strings(SerdEnv*       env,
                                 const uint8_t* name,
                                 const uint8_t* uri)
{
	const SerdNode name_node = serd_node_from_string(SERD_LITERAL, name);
	const SerdNode uri_node  = serd_node_from_string(SERD_URI, uri);

	return serd_env_set_prefix(env, &name_node, &uri_node);
}

static inline bool
is_nameChar(const uint8_t c)
{
	return is_alpha(c) || is_digit(c) || c == '_';
}

/**
   Return true iff @c buf is a valid prefixed name suffix.
   TODO: This is more strict than it should be.
*/
static inline bool
is_name(const uint8_t* buf, size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		if (!is_nameChar(buf[i])) {
			return false;
		}
	}
	return true;
}

SERD_API
bool
serd_env_qualify(const SerdEnv*  env,
                 const SerdNode* uri,
                 SerdNode*       prefix_name,
                 SerdChunk*      suffix)
{
	for (size_t i = 0; i < env->n_prefixes; ++i) {
		const SerdNode* const prefix_uri = &env->prefixes[i].uri;
		if (uri->n_bytes >= prefix_uri->n_bytes) {
			if (!strncmp((const char*)uri->buf,
			             (const char*)prefix_uri->buf,
			             prefix_uri->n_bytes)) {
				*prefix_name = env->prefixes[i].name;
				suffix->buf = uri->buf + prefix_uri->n_bytes;
				suffix->len = uri->n_bytes - prefix_uri->n_bytes;
				if (is_name(suffix->buf, suffix->len)) {
					return true;
				}
			}
		}
	}
	return false;
}

SERD_API
SerdStatus
serd_env_expand(const SerdEnv*  env,
                const SerdNode* qname,
                SerdChunk*      uri_prefix,
                SerdChunk*      uri_suffix)
{
	const uint8_t* const colon = (const uint8_t*)memchr(
		qname->buf, ':', qname->n_bytes + 1);
	if (!colon) {
		return SERD_ERR_BAD_ARG;  // Illegal qname
	}

	const size_t            name_len = colon - qname->buf;
	const SerdPrefix* const prefix   = serd_env_find(env, qname->buf, name_len);
	if (prefix) {
		uri_prefix->buf = prefix->uri.buf;
		uri_prefix->len = prefix->uri.n_bytes;
		uri_suffix->buf = colon + 1;
		uri_suffix->len = qname->n_bytes - (colon - qname->buf) - 1;
		return SERD_SUCCESS;
	}
	return SERD_ERR_NOT_FOUND;
}

SERD_API
SerdNode
serd_env_expand_node(const SerdEnv*  env,
                     const SerdNode* node)
{
	switch (node->type) {
	case SERD_CURIE: {
		SerdChunk prefix;
		SerdChunk suffix;
		if (serd_env_expand(env, node, &prefix, &suffix)) {
			return SERD_NODE_NULL;
		}
		const size_t len = prefix.len + suffix.len;  // FIXME: UTF-8?
		SerdNode     ret = { NULL, len, len, 0, SERD_URI };
		ret.buf = (uint8_t*)malloc(ret.n_bytes + 1);
		snprintf((char*)ret.buf, ret.n_bytes + 1,
		         "%s%s", prefix.buf, suffix.buf);
		return ret;
	}
	case SERD_URI: {
		SerdURI ignored;
		return serd_node_new_uri_from_node(node, &env->base_uri, &ignored);
	}
	default:
		return SERD_NODE_NULL;
	}
}

SERD_API
void
serd_env_foreach(const SerdEnv* env,
                 SerdPrefixSink func,
                 void*          handle)
{
	for (size_t i = 0; i < env->n_prefixes; ++i) {
		func(handle, &env->prefixes[i].name, &env->prefixes[i].uri);
	}
}

/**
   @file src/node.c
*/

#include <stdlib.h>
#include <string.h>

#include <math.h>
#include <float.h>

SERD_API
SerdNode
serd_node_from_string(SerdType type, const uint8_t* buf)
{
	uint32_t     flags       = 0;
	size_t       buf_n_bytes = 0;
	const size_t buf_n_chars = serd_strlen(buf, &buf_n_bytes, &flags);
	SerdNode ret = { buf, buf_n_bytes, buf_n_chars, flags, type };
	return ret;
}

SERD_API
SerdNode
serd_node_copy(const SerdNode* node)
{
	if (!node) {
		return SERD_NODE_NULL;
	}

	SerdNode copy = *node;
	uint8_t* buf  = (uint8_t*)malloc(copy.n_bytes + 1);
	memcpy(buf, node->buf, copy.n_bytes + 1);
	copy.buf = buf;
	return copy;
}

SERD_API
bool
serd_node_equals(const SerdNode* a, const SerdNode* b)
{
	return (a == b)
		|| (a->type == b->type
		    && a->n_bytes == b->n_bytes
		    && a->n_chars == b->n_chars
		    && ((a->buf == b->buf) || !memcmp((const char*)a->buf,
		                                      (const char*)b->buf,
		                                      a->n_bytes + 1)));
}

static size_t
serd_uri_string_length(const SerdURI* uri)
{
	size_t len = uri->path_base.len;

#define ADD_LEN(field, n_delims) \
	if ((field).len) { len += (field).len + (n_delims); }

	ADD_LEN(uri->path,      1);  // + possible leading `/'
	ADD_LEN(uri->scheme,    1);  // + trailing `:'
	ADD_LEN(uri->authority, 2);  // + leading `//'
	ADD_LEN(uri->query,     1);  // + leading `?'
	ADD_LEN(uri->fragment,  1);  // + leading `#'

	return len + 2;  // + 2 for authority `//'
}

static size_t
string_sink(const void* buf, size_t len, void* stream)
{
	uint8_t** ptr = (uint8_t**)stream;
	memcpy(*ptr, buf, len);
	*ptr += len;
	return len;
}

SERD_API
SerdNode
serd_node_new_uri_from_node(const SerdNode* uri_node,
                            const SerdURI*  base,
                            SerdURI*        out)
{
	return (uri_node->type == SERD_URI)
		? serd_node_new_uri_from_string(uri_node->buf, base, out)
		: SERD_NODE_NULL;
}

SERD_API
SerdNode
serd_node_new_uri_from_string(const uint8_t* str,
                              const SerdURI* base,
                              SerdURI*       out)
{
	if (!str || str[0] == '\0') {
		return serd_node_new_uri(base, NULL, out);  // Empty URI => Base URI
	}
	SerdURI uri;
	serd_uri_parse(str, &uri);
	return serd_node_new_uri(&uri, base, out);  // Resolve/Serialise
}

SERD_API
SerdNode
serd_node_new_uri(const SerdURI* uri, const SerdURI* base, SerdURI* out)
{
	SerdURI abs_uri = *uri;
	if (base) {
		serd_uri_resolve(uri, base, &abs_uri);
	}

	const size_t len = serd_uri_string_length(&abs_uri);
	uint8_t*     buf = (uint8_t*)malloc(len + 1);

	SerdNode node = { buf, len, len, 0, SERD_URI };  // FIXME: UTF-8

	uint8_t*     ptr        = buf;
	const size_t actual_len = serd_uri_serialise(&abs_uri, string_sink, &ptr);

	buf[actual_len] = '\0';
	node.n_bytes    = actual_len;
	node.n_chars    = actual_len;

	if (out) {
		serd_uri_parse(buf, out);  // TODO: cleverly avoid double parse
	}

	return node;
}

SERD_API
SerdNode
serd_node_new_decimal(double d, unsigned frac_digits)
{
	const double   abs_d      = fabs(d);
	const unsigned int_digits = (unsigned)fmax(1.0, ceil(log10(abs_d)));
	char*          buf        = (char*)calloc(int_digits + frac_digits + 3, 1);
	SerdNode       node       = { (const uint8_t*)buf, 0, 0, 0, SERD_LITERAL };
	const double   int_part   = floor(abs_d);

	// Point s to decimal point location
	char* s = buf + int_digits;
	if (d < 0.0) {
		*buf = '-';
		++s;
	}

	// Write integer part (right to left)
	char*    t   = s - 1;
	uint64_t dec = (uint64_t)int_part;
	do {
		*t-- = '0' + (dec % 10);
	} while ((dec /= 10) > 0);

	*s++ = '.';

	// Write fractional part (right to left)
	double frac_part = fabs(d - int_part);
	if (frac_part < DBL_EPSILON) {
		*s++ = '0';
		node.n_bytes = node.n_chars = (s - buf);
	} else {
		uint64_t frac = frac_part * pow(10.0, (int)frac_digits) + 0.5;
		s += frac_digits - 1;
		unsigned i = 0;

		// Skip trailing zeros
		for (; i < frac_digits - 1 && !(frac % 10); ++i, --s, frac /= 10) {}

		node.n_bytes = node.n_chars = (s - buf) + 1;

		// Write digits from last trailing zero to decimal point
		for (; i < frac_digits; ++i) {
			*s-- = '0' + (frac % 10);
			frac /= 10;
		}
	}

	return node;
}

SERD_API
SerdNode
serd_node_new_integer(int64_t i)
{
	int64_t        abs_i  = (i < 0) ? -i : i;
	const unsigned digits = fmax(1.0, ceil(log10((double)abs_i + 1)));
	char*          buf    = (char*)calloc(digits + 2, 1);
	SerdNode       node   = { (const uint8_t*)buf, 0, 0, 0, SERD_LITERAL };

	// Point s to the end
	char* s = buf + digits - 1;
	if (i < 0) {
		*buf = '-';
		++s;
	}

	node.n_bytes = node.n_chars = (s - buf) + 1;

	// Write integer part (right to left)
	do {
		*s-- = '0' + (abs_i % 10);
	} while ((abs_i /= 10) > 0);

	return node;
}

/**
   Base64 encoding table.
   @see <a href="http://tools.ietf.org/html/rfc3548#section-3">RFC3986 S3</a>.
*/
static const uint8_t b64_map[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
   Encode 3 raw bytes to 4 base64 characters.
*/
static inline void
encode_chunk(uint8_t out[4], const uint8_t in[3], size_t n_in)
{
	out[0] = b64_map[in[0] >> 2];
	out[1] = b64_map[((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4)];
	out[2] = ((n_in > 1)
	          ? (b64_map[((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6)])
	          : (uint8_t)'=');
	out[3] = ((n_in > 2) ? b64_map[in[2] & 0x3F] : (uint8_t)'=');
}

SERD_API
SerdNode
serd_node_new_blob(const void* buf, size_t size, bool wrap_lines)
{
	const size_t len  = ((size + 2) / 3) * 4 + (wrap_lines ? (size / 57) : 0);
	SerdNode     node = { (uint8_t*)calloc(1, len + 2),
	                      len, len, 0, SERD_LITERAL };
	for (size_t i = 0, j = 0; i < size; i += 3, j += 4) {
		uint8_t in[4] = { 0, 0, 0, 0 };
		size_t  n_in  = MIN(3, size - i);
		memcpy(in, (const uint8_t*)buf + i, n_in);

		if (wrap_lines && i > 0 && (i % 57) == 0) {
			((uint8_t*)node.buf)[j++] = '\n';
			node.flags |= SERD_HAS_NEWLINE;
		}

		encode_chunk((uint8_t*)node.buf + j, in, n_in);
	}
	return node;
}

SERD_API
void
serd_node_free(SerdNode* node)
{
	if (node->buf) {
		free((uint8_t*)node->buf);
		node->buf = NULL;
	}
}

/**
   @file src/reader.c
*/

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NS_XSD "http://www.w3.org/2001/XMLSchema#"
#define NS_RDF "http://www.w3.org/1999/02/22-rdf-syntax-ns#"

#define TRY_THROW(exp) if (!(exp)) goto except;
#define TRY_RET(exp)   if (!(exp)) return 0;

#ifdef SERD_STACK_CHECK
#    define SERD_STACK_ASSERT_TOP(reader, ref) \
            assert(ref == reader->allocs[reader->n_allocs - 1]);
#else
#    define SERD_STACK_ASSERT_TOP(reader, ref)
#endif

typedef struct {
	const uint8_t* filename;
	unsigned       line;
	unsigned       col;
} Cursor;

typedef uint32_t uchar;

/* Reference to a node in the stack (we can not use pointers since the
   stack may be reallocated, invalidating any pointers to elements).
*/
typedef size_t Ref;

typedef struct {
	Ref                 graph;
	Ref                 subject;
	Ref                 predicate;
	SerdStatementFlags* flags;
} ReadContext;

struct SerdReaderImpl {
	void*             handle;
	void              (*free_handle)(void* ptr);
	SerdBaseSink      base_sink;
	SerdPrefixSink    prefix_sink;
	SerdStatementSink statement_sink;
	SerdEndSink       end_sink;
	SerdErrorSink     error_sink;
	Ref               rdf_first;
	Ref               rdf_rest;
	Ref               rdf_nil;
	FILE*             fd;
	SerdStack         stack;
	SerdSyntax        syntax;
	Cursor            cur;
	uint8_t*          buf;
	uint8_t*          bprefix;
	size_t            bprefix_len;
	unsigned          next_id;
	uint8_t*          read_buf;
	int32_t           read_head;  ///< Offset into read_buf
	bool              from_file;  ///< True iff reading from @ref fd
	bool              eof;
	bool              seen_genid;
#ifdef SERD_STACK_CHECK
	Ref*              allocs;     ///< Stack of push offsets
	size_t            n_allocs;   ///< Number of stack pushes
#endif
};

static int
error(SerdReader* reader, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int r	= reader->error_sink( reader->handle, reader->cur.filename, reader->cur.line, reader->cur.col, fmt, args );
	va_end(args);
	return r;
}

static int default_error_sink (void* handle, const uint8_t* filename, unsigned line, unsigned col, const char* fmt, va_list args) {
	fprintf(stderr, "error: %s:%u:%u: ", filename, line, col);
	vfprintf(stderr, fmt, args);
	return 0;
}

static inline bool
page(SerdReader* reader)
{
	reader->read_head = 0;
	size_t n_read = fread(reader->read_buf, 1, SERD_PAGE_SIZE, reader->fd);
	if (n_read == 0) {
		reader->read_buf[0] = '\0';
		reader->eof = true;
		return false;
	} else if (n_read < SERD_PAGE_SIZE) {
		reader->read_buf[n_read] = '\0';
	}
	return true;
}

static inline uint8_t
peek_byte(SerdReader* reader)
{
	return reader->read_buf[reader->read_head];
}

static inline uint8_t
eat_byte_safe(SerdReader* reader, const uint8_t byte)
{
	assert(peek_byte(reader) == byte);
	++reader->read_head;
	switch (byte) {
	case '\0': reader->eof = true; break;
	case '\n': ++reader->cur.line; reader->cur.col = 0; break;
	default:   ++reader->cur.col;
	}

	if (reader->from_file && (reader->read_head == SERD_PAGE_SIZE)) {
		page(reader);
	}
	return byte;
}

static inline uint8_t
eat_byte_check(SerdReader* reader, const uint8_t byte)
{
	const uint8_t c = peek_byte(reader);
	if (c != byte) {
		return error(reader, "expected `%c', not `%c'\n", byte, c);
	}
	return eat_byte_safe(reader, byte);
}

static inline void
eat_string(SerdReader* reader, const char* str, unsigned n)
{
	for (unsigned i = 0; i < n; ++i) {
		eat_byte_check(reader, ((const uint8_t*)str)[i]);
	}
}

static Ref
push_node_padded(SerdReader* reader, size_t maxlen,
                 SerdType type, const char* str, size_t n_bytes)
{
	uint8_t* mem = serd_stack_push(&reader->stack,
	                               sizeof(SerdNode) + maxlen + 1);

	SerdNode* const node = (SerdNode*)mem;
	node->n_bytes = node->n_chars = n_bytes;
	node->flags   = 0;
	node->type    = type;
	node->buf     = NULL;

	uint8_t* buf = mem + sizeof(SerdNode);
	memcpy(buf, str, n_bytes + 1);

#ifdef SERD_STACK_CHECK
	reader->allocs = realloc(
		reader->allocs, sizeof(uint8_t*) * (++reader->n_allocs));
	reader->allocs[reader->n_allocs - 1] = (mem - reader->stack.buf);
#endif
	return (uint8_t*)node - reader->stack.buf;
}

static Ref
push_node(SerdReader* reader, SerdType type, const char* str, size_t n_bytes)
{
	return push_node_padded(reader, n_bytes, type, str, n_bytes);
}

static inline SerdNode*
deref(SerdReader* reader, const Ref ref)
{
	if (ref) {
		SerdNode* node = (SerdNode*)(reader->stack.buf + ref);
		node->buf = (uint8_t*)node + sizeof(SerdNode);
		return node;
	}
	return NULL;
}

static inline void
push_byte(SerdReader* reader, Ref ref, const uint8_t c)
{
	SERD_STACK_ASSERT_TOP(reader, ref);
	uint8_t* const  s    = serd_stack_push(&reader->stack, 1);
	SerdNode* const node = (SerdNode*)(reader->stack.buf + ref);
	++node->n_bytes;
	if (!(c & 0x80)) {  // Starts with 0 bit, start of new character
		++node->n_chars;
	}
	*(s - 1) = c;
	*s       = '\0';
}

static inline void
push_replacement(SerdReader* reader, Ref dest)
{
	push_byte(reader, dest, 0xEF);
	push_byte(reader, dest, 0xBF);
	push_byte(reader, dest, 0xBD);
}

static Ref
pop_node(SerdReader* reader, Ref ref)
{
	if (ref && ref != reader->rdf_first && ref != reader->rdf_rest
	    && ref != reader->rdf_nil) {
#ifdef SERD_STACK_CHECK
		SERD_STACK_ASSERT_TOP(reader, ref);
		--reader->n_allocs;
#endif
		SerdNode* const node = deref(reader, ref);
		uint8_t* const  top  = reader->stack.buf + reader->stack.size;
		serd_stack_pop(&reader->stack, top - (uint8_t*)node);
	}
	return 0;
}

static inline bool
emit_statement(SerdReader* reader, ReadContext ctx, Ref o, Ref d, Ref l)
{
	bool ret = !reader->statement_sink ||
		!reader->statement_sink(
			reader->handle, *ctx.flags, deref(reader, ctx.graph),
			deref(reader, ctx.subject), deref(reader, ctx.predicate),
			deref(reader, o), deref(reader, d), deref(reader, l));
	*ctx.flags &= SERD_ANON_CONT|SERD_LIST_CONT;  // Preserve only cont flags
	return ret;
}

static bool
read_collection(SerdReader* reader, ReadContext ctx, Ref* dest);

static bool
read_predicateObjectList(SerdReader* reader, ReadContext ctx);

// [40]	hex	::=	[#x30-#x39] | [#x41-#x46]
static inline uint8_t
read_hex(SerdReader* reader)
{
	const uint8_t c = peek_byte(reader);
	if (in_range(c, 0x30, 0x39) || in_range(c, 0x41, 0x46)) {
		return eat_byte_safe(reader, c);
	} else {
		return error(reader, "illegal hexadecimal digit `%c'\n", c);
	}
}

static inline bool
read_hex_escape(SerdReader* reader, unsigned length, Ref dest)
{
	uint8_t buf[9] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	for (unsigned i = 0; i < length; ++i) {
		if (!(buf[i] = read_hex(reader))) {
			return false;
		}
	}

	uint32_t c;
	sscanf((const char*)buf, "%X", &c);

	unsigned size = 0;
	if (c < 0x00000080) {
		size = 1;
	} else if (c < 0x00000800) {
		size = 2;
	} else if (c < 0x00010000) {
		size = 3;
	} else if (c < 0x00110000) {
		size = 4;
	} else {
		error(reader, "unicode character 0x%X out of range\n", c);
		push_replacement(reader, dest);
		return true;
	}

	// Build output in buf
	// (Note # of bytes = # of leading 1 bits in first byte)
	switch (size) {
	case 4:
		buf[3] = 0x80 | (uint8_t)(c & 0x3F);
		c >>= 6;
		c |= (16 << 12);  // set bit 4
	case 3:
		buf[2] = 0x80 | (uint8_t)(c & 0x3F);
		c >>= 6;
		c |= (32 << 6);  // set bit 5
	case 2:
		buf[1] = 0x80 | (uint8_t)(c & 0x3F);
		c >>= 6;
		c |= 0xC0;  // set bits 6 and 7
	case 1:
		buf[0] = (uint8_t)c;
	}

	for (unsigned i = 0; i < size; ++i) {
		push_byte(reader, dest, buf[i]);
	}
	return true;
}

static inline bool
read_character_escape(SerdReader* reader, Ref dest)
{
	switch (peek_byte(reader)) {
	case '\\':
		push_byte(reader, dest, eat_byte_safe(reader, '\\'));
		return true;
	case 'u':
		eat_byte_safe(reader, 'u');
		return read_hex_escape(reader, 4, dest);
	case 'U':
		eat_byte_safe(reader, 'U');
		return read_hex_escape(reader, 8, dest);
	default:
		return false;
	}
}

static inline bool
read_echaracter_escape(SerdReader* reader, Ref dest, SerdNodeFlags* flags)
{
	switch (peek_byte(reader)) {
	case 't':
		eat_byte_safe(reader, 't');
		push_byte(reader, dest, '\t');
		return true;
	case 'n':
		*flags |= SERD_HAS_NEWLINE;
		eat_byte_safe(reader, 'n');
		push_byte(reader, dest, '\n');
		return true;
	case 'r':
		*flags |= SERD_HAS_NEWLINE;
		eat_byte_safe(reader, 'r');
		push_byte(reader, dest, '\r');
		return true;
	default:
		return read_character_escape(reader, dest);
	}
}

static inline bool
read_scharacter_escape(SerdReader* reader, Ref dest, SerdNodeFlags* flags)
{
	switch (peek_byte(reader)) {
	case '"':
		*flags |= SERD_HAS_QUOTE;
		push_byte(reader, dest, eat_byte_safe(reader, '"'));
		return true;
	default:
		return read_echaracter_escape(reader, dest, flags);
	}
}

static inline bool
read_ucharacter_escape(SerdReader* reader, Ref dest)
{
	SerdNodeFlags flags = 0;
	switch (peek_byte(reader)) {
	case '>':
		push_byte(reader, dest, eat_byte_safe(reader, '>'));
		return true;
	default:
		return read_echaracter_escape(reader, dest, &flags);
	}
}

static inline SerdStatus
bad_char(SerdReader* reader, Ref dest, const char* fmt, uint8_t c)
{
	error(reader, fmt, c);
	push_replacement(reader, dest);

	// Skip bytes until the next start byte
	for (uint8_t c = peek_byte(reader); (c & 0x80);) {
		eat_byte_safe(reader, c);
		c = peek_byte(reader);
	}

	return SERD_SUCCESS;
}

static SerdStatus
read_utf8_character(SerdReader* reader, Ref dest, const uint8_t c)
{
	unsigned size = 1;
	if ((c & 0xE0) == 0xC0) {  // Starts with `110'
		size = 2;
	} else if ((c & 0xF0) == 0xE0) {  // Starts with `1110'
		size = 3;
	} else if ((c & 0xF8) == 0xF0) {  // Starts with `11110'
		size = 4;
	} else {
		return bad_char(reader, dest, "invalid UTF-8 start 0x%X\n",
		                eat_byte_safe(reader, c));
	}

	char bytes[4];
	bytes[0] = eat_byte_safe(reader, c);

	// Check character validity
	for (unsigned i = 1; i < size; ++i) {
		if (((bytes[i] = peek_byte(reader)) & 0x80) == 0) {
			return bad_char(reader, dest, "invalid UTF-8 continuation 0x%X\n",
			                bytes[i]);
		}
		eat_byte_safe(reader, bytes[i]);
	}

	// Emit character
	for (unsigned i = 0; i < size; ++i) {
		push_byte(reader, dest, bytes[i]);
	}
	return SERD_SUCCESS;
}

// [38] character ::= '\u' hex hex hex hex
//    | '\U' hex hex hex hex hex hex hex hex
//    | '\\'
//    | [#x20-#x5B] | [#x5D-#x10FFFF]
static inline SerdStatus
read_character(SerdReader* reader, Ref dest)
{
	const uint8_t c = peek_byte(reader);
	assert(c != '\\');  // Only called from methods that handle escapes first
	if (c == '\0') {
		error(reader, "unexpected end of file\n", c);
		return SERD_ERR_BAD_SYNTAX;
	} else if (c < 0x20) {
		return bad_char(reader, dest,
		                "unexpected control character 0x%X\n",
		                eat_byte_safe(reader, c));
	} else if (!(c & 0x80)) {
		push_byte(reader, dest, eat_byte_safe(reader, c));
		return SERD_SUCCESS;
	} else {
		return read_utf8_character(reader, dest, c);
	}
}

// [43] lcharacter ::= echaracter | '\"' | #x9 | #xA | #xD
static inline SerdStatus
read_lcharacter(SerdReader* reader, Ref dest, SerdNodeFlags* flags)
{
	const uint8_t c = peek_byte(reader);
	uint8_t       buf[2];
	switch (c) {
	case '"':
		eat_byte_safe(reader, '\"');
		buf[0] = eat_byte_safe(reader, peek_byte(reader));
		buf[1] = eat_byte_safe(reader, peek_byte(reader));
		if (buf[0] == '\"' && buf[1] == '\"') {
			return SERD_FAILURE;
		} else {
			*flags |= SERD_HAS_QUOTE;
			push_byte(reader, dest, c);
			push_byte(reader, dest, buf[0]);
			push_byte(reader, dest, buf[1]);
			return SERD_SUCCESS;
		}
	case '\\':
		eat_byte_safe(reader, '\\');
		if (read_scharacter_escape(reader, dest, flags)) {
			return SERD_SUCCESS;
		} else {
			error(reader, "illegal escape `\\%c'\n", peek_byte(reader));
			return SERD_ERR_BAD_SYNTAX;
		}
	case 0xA: case 0xD:
		*flags |= SERD_HAS_NEWLINE;
	case 0x9:
		push_byte(reader, dest, eat_byte_safe(reader, c));
		return SERD_SUCCESS;
	default:
		return read_character(reader, dest);
	}
}

// [42] scharacter ::= ( echaracter - #x22 ) | '\"'
static inline SerdStatus
read_scharacter(SerdReader* reader, Ref dest, SerdNodeFlags* flags)
{
	uint8_t c = peek_byte(reader);
	switch (c) {
	case '\\':
		eat_byte_safe(reader, '\\');
		if (read_scharacter_escape(reader, dest, flags)) {
			return SERD_SUCCESS;
		} else {
			error(reader, "illegal escape `\\%c'\n", peek_byte(reader));
			return SERD_ERR_BAD_SYNTAX;
		}
	case '\"':
		return SERD_FAILURE;
	default:
		return read_character(reader, dest);
	}
}

// Spec: [41] ucharacter ::= ( character - #x3E ) | '\>'
// Impl: [41] ucharacter ::= ( echaracter - #x3E ) | '\>'
static inline SerdStatus
read_ucharacter(SerdReader* reader, Ref dest)
{
	const uint8_t c = peek_byte(reader);
	switch (c) {
	case '\\':
		eat_byte_safe(reader, '\\');
		if (read_ucharacter_escape(reader, dest)) {
			return SERD_SUCCESS;
		} else {
			error(reader, "illegal escape `\\%c'\n", peek_byte(reader));
			return SERD_FAILURE;
		}
	case '>':
		return SERD_FAILURE;
	default:
		return read_character(reader, dest);
	}
}

// [10] comment ::= '#' ( [^#xA #xD] )*
static void
read_comment(SerdReader* reader)
{
	eat_byte_safe(reader, '#');
	uint8_t c;
	while (((c = peek_byte(reader)) != 0xA) && (c != 0xD)) {
		eat_byte_safe(reader, c);
	}
}

// [24] ws ::= #x9 | #xA | #xD | #x20 | comment
static inline bool
read_ws(SerdReader* reader)
{
	const uint8_t c = peek_byte(reader);
	switch (c) {
	case 0x9: case 0xA: case 0xD: case 0x20:
		eat_byte_safe(reader, c);
		return true;
	case '#':
		read_comment(reader);
		return true;
	default:
		return false;
	}
}

static inline bool
read_ws_star(SerdReader* reader)
{
	while (read_ws(reader)) {}
	return true;
}

static inline bool
read_ws_plus(SerdReader* reader)
{
	TRY_RET(read_ws(reader));
	return read_ws_star(reader);
}

static inline bool
peek_delim(SerdReader* reader, const char delim)
{
	read_ws_star(reader);
	return peek_byte(reader) == delim;
}

static inline bool
eat_delim(SerdReader* reader, const char delim)
{
	if (peek_delim(reader, delim)) {
		eat_byte_safe(reader, delim);
		return read_ws_star(reader);
	}
	return false;
}

// [37] longString ::= #x22 #x22 #x22 lcharacter* #x22 #x22 #x22
static Ref
read_longString(SerdReader* reader, SerdNodeFlags* flags)
{
	Ref        ref = push_node(reader, SERD_LITERAL, "", 0);
	SerdStatus st;
	while (!(st = read_lcharacter(reader, ref, flags))) {}
	if (st < SERD_ERR_UNKNOWN) {
		return ref;
	}
	return pop_node(reader, ref);
}

// [36] string ::= #x22 scharacter* #x22
static Ref
read_string(SerdReader* reader, SerdNodeFlags* flags)
{
	Ref        ref = push_node(reader, SERD_LITERAL, "", 0);
	SerdStatus st;
	while (!(st = read_scharacter(reader, ref, flags))) {}
	if (st < SERD_ERR_UNKNOWN) {
		eat_byte_check(reader, '\"');
		return ref;
	}
	return pop_node(reader, ref);
}

// [35] quotedString ::= string | longString
static Ref
read_quotedString(SerdReader* reader, SerdNodeFlags* flags)
{
	eat_byte_safe(reader, '\"');  // q1
	const uint8_t q2 = peek_byte(reader);
	if (q2 != '\"') {  // Non-empty single-quoted string
		return read_string(reader, flags);
	}

	eat_byte_safe(reader, q2);
	const uint8_t q3 = peek_byte(reader);
	if (q3 != '\"') {  // Empty single-quoted string
		return push_node(reader, SERD_LITERAL, "", 0);
	}

	eat_byte_safe(reader, '\"');
	return read_longString(reader, flags);
}

// [34] relativeURI ::= ucharacter*
static inline Ref
read_relativeURI(SerdReader* reader)
{
	Ref ref = push_node(reader, SERD_URI, "", 0);
	SerdStatus st;
	while (!(st = read_ucharacter(reader, ref))) {}
	if (st < SERD_ERR_UNKNOWN) {
		return ref;
	}
	return pop_node(reader, ref);
}

// [30] nameStartChar ::= [A-Z] | "_" | [a-z]
//    | [#x00C0-#x00D6] | [#x00D8-#x00F6] | [#x00F8-#x02FF] | [#x0370-#x037D]
//    | [#x037F-#x1FFF] | [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF]
//    | [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] | [#x10000-#xEFFFF]
static inline uchar
read_nameStartChar(SerdReader* reader)
{
	const uint8_t c = peek_byte(reader);
	if (c == '_' || is_alpha(c)) {  // TODO: not strictly correct
		return eat_byte_safe(reader, c);
	}
	return 0;
}

// [31] nameChar ::= nameStartChar | '-' | [0-9]
//    | #x00B7 | [#x0300-#x036F] | [#x203F-#x2040]
static inline uchar
read_nameChar(SerdReader* reader)
{
	uchar c = read_nameStartChar(reader);
	if (c)
		return c;

	switch ((c = peek_byte(reader))) {
	case '-': case 0xB7: case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		return eat_byte_safe(reader, c);
	default:  // TODO: 0x300-0x036F | 0x203F-0x2040
		return 0;
	}
	return 0;
}

// [33] prefixName ::= ( nameStartChar - '_' ) nameChar*
static Ref
read_prefixName(SerdReader* reader, Ref dest)
{
	uint8_t c = peek_byte(reader);
	if (c == '_') {
		error(reader, "unexpected `_'\n");
		return pop_node(reader, dest);
	}
	TRY_RET(c = read_nameStartChar(reader));
	if (!dest) {
		dest = push_node(reader, SERD_CURIE, "", 0);
	}
	push_byte(reader, dest, c);
	while ((c = read_nameChar(reader))) {
		push_byte(reader, dest, c);
	}
	return dest;
}

// [32] name ::= nameStartChar nameChar*
static Ref
read_name(SerdReader* reader, Ref dest)
{
	uchar c = read_nameStartChar(reader);
	if (!c) {
		return 0;
	}
	do {
		push_byte(reader, dest, c);
	} while ((c = read_nameChar(reader)) != 0);
	return dest;
}

// [29] language ::= [a-z]+ ('-' [a-z0-9]+ )*
static Ref
read_language(SerdReader* reader)
{
	uint8_t c = peek_byte(reader);
	if (!in_range(c, 'a', 'z')) {
		return error(reader, "unexpected `%c'\n", c);
	}
	Ref ref = push_node(reader, SERD_LITERAL, "", 0);
	push_byte(reader, ref, eat_byte_safe(reader, c));
	while ((c = peek_byte(reader)) && in_range(c, 'a', 'z')) {
		push_byte(reader, ref, eat_byte_safe(reader, c));
	}
	while (peek_byte(reader) == '-') {
		push_byte(reader, ref, eat_byte_safe(reader, '-'));
		while ((c = peek_byte(reader)) && (
			       in_range(c, 'a', 'z') || in_range(c, '0', '9'))) {
			push_byte(reader, ref, eat_byte_safe(reader, c));
		}
	}
	return ref;
}

// [28] uriref ::= '<' relativeURI '>'
static Ref
read_uriref(SerdReader* reader)
{
	TRY_RET(eat_byte_check(reader, '<'));
	Ref const str = read_relativeURI(reader);
	if (str && eat_byte_check(reader, '>')) {
		return str;
	}
	return pop_node(reader, str);
}

// [27] qname ::= prefixName? ':' name?
static Ref
read_qname(SerdReader* reader, Ref dest, bool read_prefix)
{
	Ref str = 0;
	if (!dest) {
		dest = push_node(reader, SERD_CURIE, "", 0);
	}
	if (read_prefix) {
		read_prefixName(reader, dest);
	}
	TRY_THROW(eat_byte_check(reader, ':'));
	push_byte(reader, dest, ':');
	str = read_name(reader, dest);
	return str ? str : dest;
except:
	return pop_node(reader, dest);
}

static bool
read_0_9(SerdReader* reader, Ref str, bool at_least_one)
{
	uint8_t c;
	if (at_least_one) {
		if (!is_digit((c = peek_byte(reader)))) {
			return error(reader, "expected digit\n");
		}
		push_byte(reader, str, eat_byte_safe(reader, c));
	}
	while (is_digit((c = peek_byte(reader)))) {
		push_byte(reader, str, eat_byte_safe(reader, c));
	}
	return true;
}

// [19] exponent ::= [eE] ('-' | '+')? [0-9]+
// [18] decimal ::= ( '-' | '+' )? ( [0-9]+ '.' [0-9]*
//                                  | '.' ([0-9])+
//                                  | ([0-9])+ )
// [17] double  ::= ( '-' | '+' )? ( [0-9]+ '.' [0-9]* exponent
//                                  | '.' ([0-9])+ exponent
//                                  | ([0-9])+ exponent )
// [16] integer ::= ( '-' | '+' ) ? [0-9]+
static bool
read_number(SerdReader* reader, Ref* dest, Ref* datatype)
{
	#define XSD_DECIMAL NS_XSD "decimal"
	#define XSD_DOUBLE  NS_XSD "double"
	#define XSD_INTEGER NS_XSD "integer"
	Ref     ref         = push_node(reader, SERD_LITERAL, "", 0);
	uint8_t c           = peek_byte(reader);
	bool    has_decimal = false;
	if (c == '-' || c == '+') {
		push_byte(reader, ref, eat_byte_safe(reader, c));
	}
	if ((c = peek_byte(reader)) == '.') {
		has_decimal = true;
		// decimal case 2 (e.g. '.0' or `-.0' or `+.0')
		push_byte(reader, ref, eat_byte_safe(reader, c));
		TRY_THROW(read_0_9(reader, ref, true));
	} else {
		// all other cases ::= ( '-' | '+' ) [0-9]+ ( . )? ( [0-9]+ )? ...
		assert(is_digit(c));
		read_0_9(reader, ref, true);
		if ((c = peek_byte(reader)) == '.') {
			has_decimal = true;
			push_byte(reader, ref, eat_byte_safe(reader, c));
			read_0_9(reader, ref, false);
		}
	}
	c = peek_byte(reader);
	if (c == 'e' || c == 'E') {
		// double
		push_byte(reader, ref, eat_byte_safe(reader, c));
		switch ((c = peek_byte(reader))) {
		case '+': case '-':
			push_byte(reader, ref, eat_byte_safe(reader, c));
		default: break;
		}
		read_0_9(reader, ref, true);
		*datatype = push_node(reader, SERD_URI,
		                      XSD_DOUBLE, sizeof(XSD_DOUBLE) - 1);
	} else if (has_decimal) {
		*datatype = push_node(reader, SERD_URI,
		                      XSD_DECIMAL, sizeof(XSD_DECIMAL) - 1);
	} else {
		*datatype = push_node(reader, SERD_URI,
		                      XSD_INTEGER, sizeof(XSD_INTEGER) - 1);
	}
	*dest = ref;
	return true;
except:
	pop_node(reader, *datatype);
	pop_node(reader, ref);
	return false;
}

// [25] resource ::= uriref | qname
static bool
read_resource(SerdReader* reader, Ref* dest)
{
	switch (peek_byte(reader)) {
	case '<':
		*dest = read_uriref(reader);
		break;
	default:
		*dest = read_qname(reader, 0, true);
	}
	return *dest != 0;
}

static bool
read_literal(SerdReader* reader, Ref* dest,
             Ref* datatype, Ref* lang, SerdNodeFlags* flags)
{
	Ref str = read_quotedString(reader, flags);
	if (!str) {
		return false;
	}

	switch (peek_byte(reader)) {
	case '^':
		eat_byte_safe(reader, '^');
		eat_byte_check(reader, '^');
		TRY_THROW(read_resource(reader, datatype));
		break;
	case '@':
		eat_byte_safe(reader, '@');
		TRY_THROW(*lang = read_language(reader));
	}
	*dest = str;
	return true;
except:
	pop_node(reader, str);
	return false;
}

inline static bool
is_token_end(const uint8_t c)
{
	switch (c) {
	case 0x9: case 0xA: case 0xD: case 0x20: case '\0':
	case '#': case '.': case ';': case '<':
		return true;
	default:
		return false;
	}
}

// [9] verb ::= predicate | 'a'
static bool
read_verb(SerdReader* reader, Ref* dest)
{
	SerdNode* node;
	bool ret;
	switch (peek_byte(reader)) {
	case '<':
		ret = (*dest = read_uriref(reader));
		break;
	default:
		/* Either a qname, or "a".  Read the prefix first, and if it is in fact
		   "a", produce that instead.
		*/
		*dest = read_prefixName(reader, 0);
		node  = deref(reader, *dest);
		if (node && node->n_bytes == 1 && node->buf[0] == 'a'
		    && is_token_end(peek_byte(reader))) {
			pop_node(reader, *dest);
			ret = (*dest = push_node(reader, SERD_URI, NS_RDF "type", 47));
		} else {
			ret = (*dest = read_qname(reader, *dest, false));
		}
	}
	read_ws_star(reader);
	return ret;
}

// [26] nodeID ::= '_:' name
static Ref
read_nodeID(SerdReader* reader)
{
	eat_byte_safe(reader, '_');
	eat_byte_check(reader, ':');
	Ref ref = push_node(reader, SERD_BLANK,
	                    reader->bprefix ? (char*)reader->bprefix : "",
	                    reader->bprefix_len);
	if (!read_name(reader, ref)) {
		return error(reader, "illegal character at start of name\n");
	}
	if (reader->syntax == SERD_TURTLE) {
		const char* const buf = (const char*)deref(reader, ref)->buf;
		if (!strncmp(buf, "genid", 5)) {
			memcpy((char*)buf, "docid", 5);  // Prevent clash
			reader->seen_genid = true;
		} else if (reader->seen_genid && !strncmp(buf, "docid", 5)) {
			error(reader, "found both `genid' and `docid' blank IDs\n");
			error(reader, "resolve this with a blank ID prefix\n");
			return pop_node(reader, ref);
		}
	}
	return ref;
}

static void
set_blank_id(SerdReader* reader, Ref ref, size_t buf_size)
{
	SerdNode*   node   = deref(reader, ref);
	const char* prefix = reader->bprefix ? (const char*)reader->bprefix : "";
	node->n_bytes = node->n_chars = snprintf(
		(char*)node->buf, buf_size, "%sgenid%u", prefix, reader->next_id++);
}

static size_t
genid_size(SerdReader* reader)
{
	return reader->bprefix_len + 5 + 10 + 1;  // + "genid" + UINT32_MAX + \0
}

static Ref
blank_id(SerdReader* reader)
{
	Ref ref = push_node_padded(reader, genid_size(reader), SERD_BLANK, "", 0);
	set_blank_id(reader, ref, genid_size(reader));
	return ref;
}

// Spec: [21] blank ::= nodeID | '[]'
//          | '[' predicateObjectList ']' | collection
// Impl: [21] blank ::= nodeID | '[' ws* ']'
//          | '[' ws* predicateObjectList ws* ']' | collection
static bool
read_blank(SerdReader* reader, ReadContext ctx, bool subject, Ref* dest)
{
	const SerdStatementFlags old_flags = *ctx.flags;
	switch (peek_byte(reader)) {
	case '_':
		return (*dest = read_nodeID(reader));
	case '[':
		eat_byte_safe(reader, '[');
		const bool empty = peek_delim(reader, ']');
		if (empty) {
			*ctx.flags |= (subject) ? SERD_EMPTY_S : SERD_EMPTY_O;
		} else {
			*ctx.flags |= (subject) ? SERD_ANON_S_BEGIN : SERD_ANON_O_BEGIN;
		}

		*dest = blank_id(reader);
		if (ctx.subject) {
			TRY_RET(emit_statement(reader, ctx, *dest, 0, 0));
		}

		ctx.subject = *dest;
		if (!empty) {
			*ctx.flags &= ~(SERD_LIST_CONT);
			if (!subject) {
				*ctx.flags |= SERD_ANON_CONT;
			}
			read_predicateObjectList(reader, ctx);
			read_ws_star(reader);
			if (reader->end_sink) {
				reader->end_sink(reader->handle, deref(reader, *dest));
			}
			*ctx.flags = old_flags;
		}
		eat_byte_check(reader, ']');
		return true;
	case '(':
		return read_collection(reader, ctx, dest);
	default:
		return error(reader, "illegal blank node\n");
	}
}

// [13] object ::= resource | blank | literal
// Recurses, calling statement_sink for every statement encountered.
// Leaves stack in original calling state (i.e. pops everything it pushes).
static bool
read_object(SerdReader* reader, ReadContext ctx)
{
	static const char* const XSD_BOOLEAN     = NS_XSD "boolean";
	static const size_t      XSD_BOOLEAN_LEN = 40;

#ifndef NDEBUG
	const size_t orig_stack_size = reader->stack.size;
#endif

	bool          ret      = false;
	bool          emit     = (ctx.subject != 0);
	SerdNode*     node     = NULL;
	Ref           o        = 0;
	Ref           datatype = 0;
	Ref           lang     = 0;
	uint32_t      flags    = 0;
	const uint8_t c        = peek_byte(reader);
	switch (c) {
	case '\0':
	case ')':
		return false;
	case '[': case '(':
		emit = false;
		// fall through
	case '_':
		TRY_THROW(ret = read_blank(reader, ctx, false, &o));
		break;
	case '<': case ':':
		TRY_THROW(ret = read_resource(reader, &o));
		break;
	case '+': case '-': case '.': case '0': case '1': case '2': case '3':
	case '4': case '5': case '6': case '7': case '8': case '9':
		TRY_THROW(ret = read_number(reader, &o, &datatype));
		break;
	case '\"':
		TRY_THROW(ret = read_literal(reader, &o, &datatype, &lang, &flags));
		break;
	default:
		/* Either a boolean literal, or a qname.  Read the prefix first, and if
		   it is in fact a "true" or "false" literal, produce that instead.
		*/
		o    = read_prefixName(reader, 0);
		node = deref(reader, o);
		if (node && is_token_end(peek_byte(reader)) &&
		    ((node->n_bytes == 4 && !memcmp(node->buf, "true", 4))
		     || (node->n_bytes == 5 && !memcmp(node->buf, "false", 5)))) {
			node->type = SERD_LITERAL;
			datatype = push_node(reader, SERD_URI,
			                     XSD_BOOLEAN, XSD_BOOLEAN_LEN);
		} else {
			o = o ? o : push_node(reader, SERD_CURIE, "", 0);
			o = read_qname(reader, o, false);
		}
		ret = o;
	}

	if (ret && emit) {
		deref(reader, o)->flags = flags;
		ret = emit_statement(reader, ctx, o, datatype, lang);
	}

except:
	pop_node(reader, lang);
	pop_node(reader, datatype);
	pop_node(reader, o);
#ifndef NDEBUG
	assert(reader->stack.size == orig_stack_size);
#endif
	return ret;
}

// Spec: [8] objectList ::= object ( ',' object )*
// Impl: [8] objectList ::= object ( ws* ',' ws* object )*
static bool
read_objectList(SerdReader* reader, ReadContext ctx)
{
	TRY_RET(read_object(reader, ctx));
	while (eat_delim(reader, ',')) {
		TRY_RET(read_object(reader, ctx));
	}
	return true;
}

// Spec: [7] predicateObjectList ::= verb objectList
//                                   (';' verb objectList)* (';')?
// Impl: [7] predicateObjectList ::= verb ws* objectList
//                                   (ws* ';' ws* verb ws+ objectList)* (';')?
static bool
read_predicateObjectList(SerdReader* reader, ReadContext ctx)
{
	TRY_RET(read_verb(reader, &ctx.predicate));
	TRY_THROW(read_objectList(reader, ctx));
	ctx.predicate = pop_node(reader, ctx.predicate);
	while (eat_delim(reader, ';')) {
		switch (peek_byte(reader)) {
		case '.': case ']':
			return true;
		default:
			TRY_THROW(read_verb(reader, &ctx.predicate));
			TRY_THROW(read_objectList(reader, ctx));
			ctx.predicate = pop_node(reader, ctx.predicate);
		}
	}
	pop_node(reader, ctx.predicate);
	return true;
except:
	pop_node(reader, ctx.predicate);
	return false;
}

static bool
end_collection(SerdReader* reader, ReadContext ctx, Ref n1, Ref n2, bool ret)
{
	pop_node(reader, n2);
	pop_node(reader, n1);
	*ctx.flags &= ~SERD_LIST_CONT;
	return ret && (eat_byte_safe(reader, ')') == ')');
}

// [22] itemList   ::= object+
// [23] collection ::= '(' itemList? ')'
static bool
read_collection(SerdReader* reader, ReadContext ctx, Ref* dest)
{
	eat_byte_safe(reader, '(');
	bool end = peek_delim(reader, ')');
	*dest = end ? reader->rdf_nil : blank_id(reader);
	if (ctx.subject) {
		// subject predicate _:head
		*ctx.flags |= (end ? 0 : SERD_LIST_O_BEGIN);
		TRY_RET(emit_statement(reader, ctx, *dest, 0, 0));
		*ctx.flags |= SERD_LIST_CONT;
	} else {
		*ctx.flags |= (end ? 0 : SERD_LIST_S_BEGIN);
	}

	if (end) {
		return end_collection(reader, ctx, 0, 0, true);
	}

	/* The order of node allocation here is necessarily not in stack order,
	   so we create two nodes and recycle them throughout. */
	Ref n1   = push_node_padded(reader, genid_size(reader), SERD_BLANK, "", 0);
	Ref n2   = 0;
	Ref node = n1;
	Ref rest = 0;

	ctx.subject = *dest;
	while (!(end = peek_delim(reader, ')'))) {
		// _:node rdf:first object
		ctx.predicate = reader->rdf_first;
		if (!read_object(reader, ctx)) {
			return end_collection(reader, ctx, n1, n2, false);
		}

		if (!(end = peek_delim(reader, ')'))) {
			/* Give rest a new ID.  Done as late as possible to ensure it is
			   used and > IDs generated by read_object above. */
			if (!rest) {
				rest = n2 = blank_id(reader);  // First pass, push a new node
			} else {
				set_blank_id(reader, rest, genid_size(reader));
			}
		}

		// _:node rdf:rest _:rest
		*ctx.flags |= SERD_LIST_CONT;
		ctx.predicate = reader->rdf_rest;
		TRY_RET(emit_statement(reader, ctx,
		                       (end ? reader->rdf_nil : rest), 0, 0));

		ctx.subject = rest;         // _:node = _:rest
		rest        = node;         // _:rest = (old)_:node
		node        = ctx.subject;  // invariant
	}

	return end_collection(reader, ctx, n1, n2, true);
}

// [11] subject ::= resource | blank
static Ref
read_subject(SerdReader* reader, ReadContext ctx)
{
	Ref subject = 0;
	switch (peek_byte(reader)) {
	case '[': case '(': case '_':
		read_blank(reader, ctx, true, &subject);
		break;
	default:
		read_resource(reader, &subject);
	}
	return subject;
}

// Spec: [6] triples ::= subject predicateObjectList
// Impl: [6] triples ::= subject ws+ predicateObjectList
static bool
read_triples(SerdReader* reader, ReadContext ctx)
{
	const Ref subject = read_subject(reader, ctx);
	bool      ret     = false;
	if (subject) {
		ctx.subject = subject;
		TRY_RET(read_ws_plus(reader));
		ret = read_predicateObjectList(reader, ctx);
		pop_node(reader, subject);
	}
	ctx.subject = ctx.predicate = 0;
	return ret;
}

// [5] base ::= '@base' ws+ uriref
static bool
read_base(SerdReader* reader)
{
	// `@' is already eaten in read_directive
	eat_string(reader, "base", 4);
	TRY_RET(read_ws_plus(reader));
	Ref uri;
	TRY_RET(uri = read_uriref(reader));
	if (reader->base_sink) {
		reader->base_sink(reader->handle, deref(reader, uri));
	}
	pop_node(reader, uri);
	return true;
}

// Spec: [4] prefixID ::= '@prefix' ws+ prefixName? ':' uriref
// Impl: [4] prefixID ::= '@prefix' ws+ prefixName? ':' ws* uriref
static bool
read_prefixID(SerdReader* reader)
{
	bool ret  = true;
	Ref  name = 0;
	Ref  uri  = 0;
	// `@' is already eaten in read_directive
	eat_string(reader, "prefix", 6);
	TRY_RET(read_ws_plus(reader));
	name = read_prefixName(reader, 0);
	if (!name) {
		name = push_node(reader, SERD_LITERAL, "", 0);
	}
	TRY_THROW(eat_byte_check(reader, ':') == ':');
	read_ws_star(reader);
	TRY_THROW(uri = read_uriref(reader));
	if (reader->prefix_sink) {
		ret = !reader->prefix_sink(reader->handle,
		                           deref(reader, name),
		                           deref(reader, uri));
	}
	pop_node(reader, uri);
except:
	pop_node(reader, name);
	return ret;
}

// [3] directive ::= prefixID | base
static bool
read_directive(SerdReader* reader)
{
	eat_byte_safe(reader, '@');
	switch (peek_byte(reader)) {
	case 'b': return read_base(reader);
	case 'p': return read_prefixID(reader);
	default:  return error(reader, "illegal directive\n");
	}
}

// Spec: [1] statement ::= directive '.' | triples '.' | ws+
// Impl: [1] statement ::= directive ws* '.' | triples ws* '.' | ws+
static bool
read_statement(SerdReader* reader)
{
	SerdStatementFlags flags = 0;
	ReadContext ctx = { 0, 0, 0, &flags };
	read_ws_star(reader);
	switch (peek_byte(reader)) {
	case '\0':
		reader->eof = true;
		return true;
	case '@':
		TRY_RET(read_directive(reader));
		break;
	default:
		TRY_RET(read_triples(reader, ctx));
		break;
	}
	read_ws_star(reader);
	return eat_byte_check(reader, '.');
}

// [1] turtleDoc ::= (statement)*
static bool
read_turtleDoc(SerdReader* reader)
{
	while (!reader->eof) {
		TRY_RET(read_statement(reader));
	}
	return true;
}

SERD_API
SerdReader*
serd_reader_new(SerdSyntax        syntax,
                void*             handle,
                void              (*free_handle)(void*),
                SerdBaseSink      base_sink,
                SerdPrefixSink    prefix_sink,
                SerdStatementSink statement_sink,
                SerdEndSink       end_sink,
                SerdErrorSink     error_sink)
{
	const Cursor cur = { NULL, 0, 0 };
	SerdReader*  me  = (SerdReader*)malloc(sizeof(struct SerdReaderImpl));
	me->handle           = handle;
	me->free_handle      = free_handle;
	me->base_sink        = base_sink;
	me->prefix_sink      = prefix_sink;
	me->statement_sink   = statement_sink;
	me->end_sink         = end_sink;
	me->error_sink       = error_sink ? error_sink : default_error_sink;
	me->fd               = 0;
	me->stack            = serd_stack_new(SERD_PAGE_SIZE);
	me->syntax           = syntax;
	me->cur              = cur;
	me->bprefix          = NULL;
	me->bprefix_len      = 0;
	me->next_id          = 1;
	me->read_buf         = 0;
	me->read_head        = 0;
	me->eof              = false;
	me->seen_genid       = false;
#ifdef SERD_STACK_CHECK
	me->allocs           = 0;
	me->n_allocs         = 0;
#endif

	me->rdf_first = push_node(me, SERD_URI, NS_RDF "first", 48);
	me->rdf_rest  = push_node(me, SERD_URI, NS_RDF "rest", 47);
	me->rdf_nil   = push_node(me, SERD_URI, NS_RDF "nil", 46);

	return me;
}

SERD_API
void
serd_reader_free(SerdReader* reader)
{
	pop_node(reader, reader->rdf_nil);
	pop_node(reader, reader->rdf_rest);
	pop_node(reader, reader->rdf_first);

#ifdef SERD_STACK_CHECK
	free(reader->allocs);
#endif
	free(reader->stack.buf);
	free(reader->bprefix);
	if (reader->free_handle) {
		reader->free_handle(reader->handle);
	}
	free(reader);
}

SERD_API
void*
serd_reader_get_handle(const SerdReader* reader)
{
	return reader->handle;
}

SERD_API
void
serd_reader_add_blank_prefix(SerdReader*    reader,
                             const uint8_t* prefix)
{
	free(reader->bprefix);
	reader->bprefix_len = 0;
	reader->bprefix     = NULL;
	if (prefix) {
		reader->bprefix_len = strlen((const char*)prefix);
		reader->bprefix     = (uint8_t*)malloc(reader->bprefix_len + 1);
		memcpy(reader->bprefix, prefix, reader->bprefix_len + 1);
	}
}

SERD_API
SerdStatus
serd_reader_read_file(SerdReader*    reader,
                      const uint8_t* uri)
{
	const uint8_t* path = serd_uri_to_path(uri);
	if (!path) {
		return SERD_ERR_BAD_ARG;
	}

	FILE* fd = serd_fopen((const char*)path, "r");
	if (!fd) {
		return SERD_ERR_UNKNOWN;
	}

	SerdStatus ret = serd_reader_read_file_handle(reader, fd, path);
	fclose(fd);
	return ret;
}

SERD_API
SerdStatus
serd_reader_read_file_handle(SerdReader* me, FILE* file, const uint8_t* name)
{
	const Cursor cur = { name, 1, 1 };
	me->fd        = file;
	me->read_head = 0;
	me->cur       = cur;
	me->from_file = true;
	me->eof       = false;
	me->read_buf  = (uint8_t*)serd_bufalloc(SERD_PAGE_SIZE);

	memset(me->read_buf, '\0', SERD_PAGE_SIZE);

	const bool ret = !page(me) || read_turtleDoc(me);

	free(me->read_buf);
	me->fd       = 0;
	me->read_buf = NULL;
	return ret ? SERD_SUCCESS : SERD_ERR_UNKNOWN;
}

SERD_API
SerdStatus
serd_reader_read_string(SerdReader* me, const uint8_t* utf8)
{
	const Cursor cur = { (const uint8_t*)"(string)", 1, 1 };

	me->read_buf  = (uint8_t*)utf8;
	me->read_head = 0;
	me->cur       = cur;
	me->from_file = false;
	me->eof       = false;

	const bool ret = read_turtleDoc(me);

	me->read_buf = NULL;
	return ret ? SERD_SUCCESS : SERD_ERR_UNKNOWN;
}

/**
   @file src/string.c
*/

#include <math.h>

SERD_API
const uint8_t*
serd_strerror(SerdStatus st)
{
	switch (st) {
	case SERD_SUCCESS:        return (const uint8_t*)"Success";
	case SERD_FAILURE:        return (const uint8_t*)"Non-fatal failure";
	case SERD_ERR_UNKNOWN:    return (const uint8_t*)"Unknown error";
	case SERD_ERR_BAD_SYNTAX: return (const uint8_t*)"Invalid syntax";
	case SERD_ERR_BAD_ARG:    return (const uint8_t*)"Invalid argument";
	case SERD_ERR_NOT_FOUND:  return (const uint8_t*)"Not found";
	}
	return (const uint8_t*)"Unknown error code";  // never reached
}

SERD_API
size_t
serd_strlen(const uint8_t* str, size_t* n_bytes, SerdNodeFlags* flags)
{
	size_t n_chars = 0;
	size_t i       = 0;
	*flags         = 0;
	for (; str[i]; ++i) {
		if ((str[i] & 0xC0) != 0x80) {
			// Does not start with `10', start of a new character
			++n_chars;
			switch (str[i]) {
			case '\r': case '\n':
				*flags |= SERD_HAS_NEWLINE;
				break;
			case '"':
				*flags |= SERD_HAS_QUOTE;
			}
		}
	}
	if (n_bytes) {
		*n_bytes = i;
	}
	return n_chars;
}

static inline double
read_sign(const char** sptr)
{
	double sign = 1.0;
	switch (**sptr) {
	case '-': sign = -1.0;
	case '+': ++(*sptr);
	default:  return sign;
	}
}

SERD_API
double
serd_strtod(const char* str, char** endptr)
{
	double result = 0.0;

	// Point s at the first non-whitespace character
	const char* s = str;
	while (is_space(*s)) { ++s; }

	// Read leading sign if necessary
	const double sign = read_sign(&s);

	// Parse integer part
	for (; is_digit(*s); ++s) {
		result = (result * 10.0) + (*s - '0');
	}

	// Parse fractional part
	if (*s == '.') {
		double denom = 10.0;
		for (++s; is_digit(*s); ++s) {
			result += (*s - '0') / denom;
			denom *= 10.0;
		}
	}

	// Parse exponent
	if (*s == 'e' || *s == 'E') {
		++s;
		double expt      = 0.0;
		double expt_sign = read_sign(&s);
		for (; is_digit(*s); ++s) {
			expt = (expt * 10.0) + (*s - '0');
		}
		result *= pow(10, expt * expt_sign);
	}

	*endptr = (char*)s;
	return result * sign;
}

/**
   Base64 decoding table.
   This is indexed by encoded characters and returns the numeric value used
   for decoding, shifted up by 47 to be in the range of printable ASCII.
   A '$' is a placeholder for characters not in the base64 alphabet.
*/
static const char b64_unmap[] =
	"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$m$$$ncdefghijkl$$$$$$"
	"$/0123456789:;<=>?@ABCDEFGH$$$$$$IJKLMNOPQRSTUVWXYZ[\\]^_`ab$$$$"
	"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
	"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$";

static inline uint8_t unmap(const uint8_t in) { return b64_unmap[in] - 47; }

/**
   Decode 4 base64 characters to 3 raw bytes.
*/
static inline size_t
decode_chunk(const uint8_t in[4], uint8_t out[3])
{
	out[0] = (uint8_t)(((unmap(in[0]) << 2))        | unmap(in[1]) >> 4);
	out[1] = (uint8_t)(((unmap(in[1]) << 4) & 0xF0) | unmap(in[2]) >> 2);
	out[2] = (uint8_t)(((unmap(in[2]) << 6) & 0xC0) | unmap(in[3]));
	return 1 + (in[2] != '=') + ((in[2] != '=') && (in[3] != '='));
}

SERD_API
void*
serd_base64_decode(const uint8_t* str, size_t len, size_t* size)
{
	void* buf = malloc((len * 3) / 4 + 2);
	*size = 0;
	for (size_t i = 0, j = 0; i < len; j += 3) {
		uint8_t in[] = "====";
		size_t  n_in = 0;
		for (; i < len && n_in < 4; ++n_in) {
			for (; i < len && !is_base64(str[i]); ++i) {}  // Skip junk
			in[n_in] = str[i++];
		}
		if (n_in > 1) {
			*size += decode_chunk(in, (uint8_t*)buf + j);
		}
	}
	return buf;
}

/**
   @file src/uri.c
*/

#include <stdlib.h>
#include <string.h>

// #define URI_DEBUG 1

static inline bool
is_windows_path(const uint8_t* path)
{
	return is_alpha(path[0]) && (path[1] == ':' || path[1] == '|')
		&& (path[2] == '/' || path[2] == '\\');
}

SERD_API
const uint8_t*
serd_uri_to_path(const uint8_t* uri)
{
	const uint8_t* path = uri;
	if (uri[0] == '/' || is_windows_path(uri)) {
		return uri;
	} else if (serd_uri_string_has_scheme(uri)) {
		if (strncmp((const char*)uri, "file:", 5)) {
			fprintf(stderr, "Non-file URI `%s'\n", uri);
			return NULL;
		} else if (!strncmp((const char*)uri, "file://localhost/", 17)) {
			path = uri + 16;
		} else if (!strncmp((const char*)uri, "file://", 7)) {
			path = uri + 7;
		} else {
			fprintf(stderr, "Invalid file URI `%s'\n", uri);
			return NULL;
		}
		if (is_windows_path(path + 1)) {
			++path;  // Special case for terrible Windows file URIs
		}
	}
	return path;
}

SERD_API
bool
serd_uri_string_has_scheme(const uint8_t* utf8)
{
	// RFC3986: scheme ::= ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	if (!is_alpha(utf8[0])) {
		return false;  // Invalid scheme initial character, URI is relative
	}
	for (uint8_t c; (c = *++utf8) != '\0';) {
		switch (c) {
		case ':':
			return true;  // End of scheme
		case '+': case '-': case '.':
			break;  // Valid scheme character, continue
		default:
			if (!is_alpha(c) && !is_digit(c)) {
				return false;  // Invalid scheme character
			}
		}
	}

	return false;
}

#ifdef URI_DEBUG
static void
serd_uri_dump(const SerdURI* uri, FILE* file)
{
#define PRINT_PART(range, name) \
	if (range.buf) { \
		fprintf(stderr, "  " name " = "); \
		fwrite((range).buf, 1, (range).len, stderr); \
		fprintf(stderr, "\n"); \
	}

	PRINT_PART(uri->scheme,    "scheme");
	PRINT_PART(uri->authority, "authority");
	PRINT_PART(uri->path_base, "path_base");
	PRINT_PART(uri->path,      "path");
	PRINT_PART(uri->query,     "query");
	PRINT_PART(uri->fragment,  "fragment");
}
#endif

SERD_API
SerdStatus
serd_uri_parse(const uint8_t* utf8, SerdURI* uri)
{
	*uri = SERD_URI_NULL;

	const uint8_t* ptr = utf8;

	/* See http://tools.ietf.org/html/rfc3986#section-3
	   URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
	*/

	/* S3.1: scheme ::= ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
	if (is_alpha(*ptr)) {
		for (uint8_t c = *++ptr; true; c = *++ptr) {
			switch (c) {
			case '\0': case '/': case '?': case '#':
				ptr = utf8;
				goto path;  // Relative URI (starts with path by definition)
			case ':':
				uri->scheme.buf = utf8;
				uri->scheme.len = (ptr++) - utf8;
				goto maybe_authority;  // URI with scheme
			case '+': case '-': case '.':
				continue;
			default:
				if (is_alpha(c) || is_digit(c)) {
					continue;
				}
			}
		}
	}

	/* S3.2: The authority component is preceded by a double slash ("//")
	   and is terminated by the next slash ("/"), question mark ("?"),
	   or number sign ("#") character, or by the end of the URI.
	*/
maybe_authority:
	if (*ptr == '/' && *(ptr + 1) == '/') {
		ptr += 2;
		uri->authority.buf = ptr;
		for (uint8_t c; (c = *ptr) != '\0'; ++ptr) {
			switch (c) {
			case '/': goto path;
			case '?': goto query;
			case '#': goto fragment;
			default:
				++uri->authority.len;
			}
		}
	}

	/* RFC3986 S3.3: The path is terminated by the first question mark ("?")
	   or number sign ("#") character, or by the end of the URI.
	*/
path:
	switch (*ptr) {
	case '?':  goto query;
	case '#':  goto fragment;
	case '\0': goto end;
	default:  break;
	}
	uri->path.buf = ptr;
	uri->path.len = 0;
	for (uint8_t c; (c = *ptr) != '\0'; ++ptr) {
		switch (c) {
		case '?': goto query;
		case '#': goto fragment;
		default:
			++uri->path.len;
		}
	}

	/* RFC3986 S3.4: The query component is indicated by the first question
	   mark ("?") character and terminated by a number sign ("#") character
	   or by the end of the URI.
	*/
query:
	if (*ptr == '?') {
		uri->query.buf = ++ptr;
		for (uint8_t c; (c = *ptr) != '\0'; ++ptr) {
			switch (c) {
			case '#':
				goto fragment;
			default:
				++uri->query.len;
			}
		}
	}

	/* RFC3986 S3.5: A fragment identifier component is indicated by the
	   presence of a number sign ("#") character and terminated by the end
	   of the URI.
	*/
fragment:
	if (*ptr == '#') {
		uri->fragment.buf = ptr;
		while (*ptr++ != '\0') {
			++uri->fragment.len;
		}
	}

end:
	#ifdef URI_DEBUG
	fprintf(stderr, "PARSE URI <%s>\n", utf8);
	serd_uri_dump(uri, stderr);
	fprintf(stderr, "\n");
	#endif

	return SERD_SUCCESS;
}

/**
   Remove leading dot components from @c path.
   See http://tools.ietf.org/html/rfc3986#section-5.2.3
   @param up Set to the number of up-references (e.g. "../") trimmed
   @return A pointer to the new start of @path
*/
static const uint8_t*
remove_dot_segments(const uint8_t* path, size_t len, size_t* up)
{
	const uint8_t*       begin = path;
	const uint8_t* const end   = path + len;

	*up = 0;
	while (begin < end) {
		switch (begin[0]) {
		case '.':
			switch (begin[1]) {
			case '/':
				begin += 2;  // Chop leading "./"
				break;
			case '.':
				switch (begin[2]) {
				case '\0':
					++*up;
					begin += 2;  // Chop input ".."
					break;
				case '/':
					++*up;
					begin += 3;  // Chop leading "../"
					break;
				default:
					return begin;
				}
				break;
			case '\0':
				++begin;  // Chop input "." (and fall-through)
			default:
				return begin;
			}
			break;
		case '/':
			switch (begin[1]) {
			case '.':
				switch (begin[2]) {
				case '/':
					begin += 2;  // Leading "/./" => "/"
					break;
				case '.':
					switch (begin[3]) {
					case '/':
						++*up;
						begin += 3;  // Leading "/../" => "/"
					}
					break;
				default:
					return begin;
				}
			}  // else fall through
		default:
			return begin;  // Finished chopping dot components
		}
	}

	return begin;
}

SERD_API
void
serd_uri_resolve(const SerdURI* r, const SerdURI* base, SerdURI* t)
{
	// See http://tools.ietf.org/html/rfc3986#section-5.2.2

	t->path_base.buf = NULL;
	t->path_base.len = 0;
	if (r->scheme.len) {
		*t = *r;
	} else {
		if (r->authority.len) {
			t->authority = r->authority;
			t->path      = r->path;
			t->query     = r->query;
		} else {
			t->path = r->path;
			if (!r->path.len) {
				t->path_base = base->path;
				if (r->query.len) {
					t->query = r->query;
				} else {
					t->query = base->query;
				}
			} else {
				if (r->path.buf[0] != '/') {
					t->path_base = base->path;
				}
				t->query = r->query;
			}
			t->authority = base->authority;
		}
		t->scheme   = base->scheme;
		t->fragment = r->fragment;
	}

	#ifdef URI_DEBUG
	fprintf(stderr, "RESOLVE URI\nBASE:\n");
	serd_uri_dump(base, stderr);
	fprintf(stderr, "URI:\n");
	serd_uri_dump(r, stderr);
	fprintf(stderr, "RESULT:\n");
	serd_uri_dump(t, stderr);
	fprintf(stderr, "\n");
	#endif
}

SERD_API
size_t
serd_uri_serialise(const SerdURI* uri, SerdSink sink, void* stream)
{
	// See http://tools.ietf.org/html/rfc3986#section-5.3

	size_t write_size = 0;
#define WRITE(buf, len) \
	write_size += len; \
	sink((const uint8_t*)buf, len, stream);

	if (uri->scheme.buf) {
		WRITE(uri->scheme.buf, uri->scheme.len);
		WRITE(":", 1);
	}
	if (uri->authority.buf) {
		WRITE("//", 2);
		WRITE(uri->authority.buf, uri->authority.len);
	}
	if (!uri->path.buf) {
		WRITE(uri->path_base.buf, uri->path_base.len);
	} else {
		const uint8_t*       begin = uri->path.buf;
		const uint8_t* const end   = uri->path.buf + uri->path.len;

		size_t up;
		begin = remove_dot_segments(uri->path.buf, uri->path.len, &up);

		if (uri->path_base.buf) {
			// Find the up'th last slash
			const uint8_t* base_last = (uri->path_base.buf
			                            + uri->path_base.len - 1);
			++up;
			do {
				if (*base_last == '/') {
					--up;
				}
			} while (up > 0 && (--base_last > uri->path_base.buf));

			// Write base URI prefix
			if (*base_last == '/') {
				const size_t base_len = base_last - uri->path_base.buf + 1;
				WRITE(uri->path_base.buf, base_len);
			}

		} else {
			// Relative path is just query or fragment, append to base URI
			WRITE(uri->path_base.buf, uri->path_base.len);
		}

		// Write URI suffix
		WRITE(begin, end - begin);
	}
	if (uri->query.buf) {
		WRITE("?", 1);
		WRITE(uri->query.buf, uri->query.len);
	}
	if (uri->fragment.buf) {
		// Note uri->fragment.buf includes the leading `#'
		WRITE(uri->fragment.buf, uri->fragment.len);
	}
	return write_size;
}

/**
   @file src/writer.c
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NS_RDF "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
#define NS_XSD "http://www.w3.org/2001/XMLSchema#"

typedef struct {
	SerdNode graph;
	SerdNode subject;
	SerdNode predicate;
} WriteContext;

static const WriteContext WRITE_CONTEXT_NULL = {
	{ 0, 0, 0, 0, SERD_NOTHING },
	{ 0, 0, 0, 0, SERD_NOTHING },
	{ 0, 0, 0, 0, SERD_NOTHING }
};

typedef enum {
	SEP_NONE,
	SEP_END_S,       ///< End of a subject ('.')
	SEP_END_P,       ///< End of a predicate (';')
	SEP_END_O,       ///< End of an object (',')
	SEP_S_P,         ///< Between a subject and predicate (whitespace)
	SEP_P_O,         ///< Between a predicate and object (whitespace)
	SEP_ANON_BEGIN,  ///< Start of anonymous node ('[')
	SEP_ANON_END,    ///< End of anonymous node (']')
	SEP_LIST_BEGIN,  ///< Start of list ('(')
	SEP_LIST_SEP,    ///< List separator (whitespace)
	SEP_LIST_END     ///< End of list (')')
} Sep;

typedef struct {
	const char* str;               ///< Sep string
	uint8_t     len;               ///< Length of sep string
	uint8_t     space_before;      ///< Newline before sep
	uint8_t     space_after_node;  ///< Newline after sep if after node
	uint8_t     space_after_sep;   ///< Newline after sep if after sep
} SepRule;

static const SepRule rules[] = {
	{ NULL,     0, 0, 0, 0 },
	{ " .\n\n", 4, 0, 0, 0 },
	{ " ;",     2, 0, 1, 1 },
	{ " ,",     2, 0, 1, 0 },
	{ NULL,     0, 0, 1, 0 },
	{ " ",      1, 0, 0, 0 },
	{ "[",      1, 0, 1, 1 },
	{ "]",      1, 0, 0, 0 },
	{ "(",      1, 0, 0, 0 },
	{ NULL,     1, 0, 1, 0 },
	{ ")",      1, 1, 0, 0 },
	{ "\n",     1, 0, 1, 0 }
};

struct SerdWriterImpl {
	SerdSyntax   syntax;
	SerdStyle    style;
	SerdEnv*     env;
	SerdURI      base_uri;
	SerdStack    anon_stack;
	SerdBulkSink bulk_sink;
	SerdSink     sink;
	void*        stream;
	WriteContext context;
	SerdNode     list_subj;
	unsigned     list_depth;
	uint8_t*     bprefix;
	size_t       bprefix_len;
	unsigned     indent;
	Sep          last_sep;
	bool         empty;
};

typedef enum {
	WRITE_URI,
	WRITE_STRING,
	WRITE_LONG_STRING
} TextContext;

static inline WriteContext*
anon_stack_top(SerdWriter* writer)
{
	assert(!serd_stack_is_empty(&writer->anon_stack));
	return (WriteContext*)(writer->anon_stack.buf
	                       + writer->anon_stack.size - sizeof(WriteContext));
}

static void
copy_node(SerdNode* dst, const SerdNode* src)
{
	if (src) {
		dst->buf = (uint8_t*)realloc((char*)dst->buf, src->n_bytes + 1);
		dst->n_bytes = src->n_bytes;
		dst->n_chars = src->n_chars;
		dst->flags   = src->flags;
		dst->type    = src->type;
		memcpy((char*)dst->buf, src->buf, src->n_bytes + 1);
	} else {
		dst->type = SERD_NOTHING;
	}
}

static inline size_t
sink(const void* buf, size_t len, SerdWriter* writer)
{
	if (writer->style & SERD_STYLE_BULK) {
		return serd_bulk_sink_write(buf, len, &writer->bulk_sink);
	} else {
		return writer->sink(buf, len, writer->stream);
	}
}

static bool
write_text(SerdWriter* writer, TextContext ctx,
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
			sink(&utf8[i], j - i, writer);
			i = j;
			continue;
		}

		uint8_t in = utf8[i++];
		if (ctx == WRITE_LONG_STRING) {
			if (in == '\\') {
				sink("\\\\", 2, writer); continue;
			} else if (in == '\"' && i == n_bytes) {
				sink("\\\"", 2, writer); continue;  // '"' at end of string
			}
		} else {
			switch (in) {
			case '\\': sink("\\\\", 2, writer); continue;
			case '\n': sink("\\n", 2, writer);  continue;
			case '\r': sink("\\r", 2, writer);  continue;
			case '\t': sink("\\t", 2, writer);  continue;
			case '"':
				if (terminator == '"') {
					sink("\\\"", 2, writer);
					continue;
				}  // else fall-through
			default: break;
			}

			if (in == terminator) {
				snprintf(escape, sizeof(escape), "\\u%04X", terminator);
				sink(escape, 6, writer);
				continue;
			}
		}

		uint32_t c    = 0;
		size_t   size = 0;
		if ((in & 0x80) == 0) {  // Starts with `0'
			c = in & 0x7F;
			if (in_range(c, 0x20, 0x7E)
			    || (is_space(c) && ctx == WRITE_LONG_STRING)) {
				sink(&in, 1, writer);  // Print ASCII character
			} else {
				snprintf(escape, sizeof(escape), "\\u%04X", c);
				sink(escape, 6, writer);  // Escape ASCII control character
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
			sink(replacement_char, sizeof(replacement_char), writer);
			return false;
		}

		if (ctx != WRITE_URI && !(writer->style & SERD_STYLE_ASCII)) {
			// Write UTF-8 character directly to UTF-8 output
			// TODO: Always parse and validate character?
			sink(utf8 + i - 1, size, writer);
			i += size - 1;
			continue;
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
			sink(escape, 6, writer);
		} else {
			snprintf(escape, sizeof(escape), "\\U%08X", c);
			sink(escape, 10, writer);
		}
	}
	return true;
}

static void
write_newline(SerdWriter* writer)
{
	sink("\n", 1, writer);
	for (unsigned i = 0; i < writer->indent; ++i) {
		sink("\t", 1, writer);
	}
}

static void
write_sep(SerdWriter* writer, const Sep sep)
{
	const SepRule* rule = &rules[sep];
	if (rule->space_before) {
		write_newline(writer);
	}
	if (rule->str) {
		sink(rule->str, rule->len, writer);
	}
	if (    (writer->last_sep && rule->space_after_sep)
	    || (!writer->last_sep && rule->space_after_node)) {
		write_newline(writer);
	} else if (writer->last_sep && rule->space_after_node) {
		sink(" ", 1, writer);
	}
	writer->last_sep = sep;
}

static SerdStatus
reset_context(SerdWriter* writer, bool del)
{
	if (del) {
		serd_node_free(&writer->context.graph);
		serd_node_free(&writer->context.subject);
		serd_node_free(&writer->context.predicate);
		writer->context = WRITE_CONTEXT_NULL;
	} else {
		writer->context.graph.type     = SERD_NOTHING;
		writer->context.subject.type   = SERD_NOTHING;
		writer->context.predicate.type = SERD_NOTHING;
	}
	writer->empty = false;
	return SERD_SUCCESS;
}

typedef enum {
	FIELD_NONE,
	FIELD_SUBJECT,
	FIELD_PREDICATE,
	FIELD_OBJECT
} Field;

static bool
write_node(SerdWriter*        writer,
           const SerdNode*    node,
           const SerdNode*    datatype,
           const SerdNode*    lang,
           Field              field,
           SerdStatementFlags flags)
{
	SerdChunk uri_prefix;
	SerdChunk uri_suffix;
	switch (node->type) {
	case SERD_BLANK:
		if (writer->syntax != SERD_NTRIPLES
		    && ((field == FIELD_SUBJECT && (flags & SERD_ANON_S_BEGIN))
		        || (field == FIELD_OBJECT && (flags & SERD_ANON_O_BEGIN)))) {
			++writer->indent;
			write_sep(writer, SEP_ANON_BEGIN);
		} else if (writer->syntax != SERD_NTRIPLES
		           && (field == FIELD_SUBJECT && (flags & SERD_LIST_S_BEGIN))) {
			assert(writer->list_depth == 0);
			copy_node(&writer->list_subj, node);
			++writer->list_depth;
			++writer->indent;
			write_sep(writer, SEP_LIST_BEGIN);
		} else if (writer->syntax != SERD_NTRIPLES
		           && (field == FIELD_OBJECT && (flags & SERD_LIST_O_BEGIN))) {
			++writer->indent;
			++writer->list_depth;
			write_sep(writer, SEP_LIST_BEGIN);
		} else if (writer->syntax != SERD_NTRIPLES
		           && ((field == FIELD_SUBJECT && (flags & SERD_EMPTY_S))
		               || (field == FIELD_OBJECT && (flags & SERD_EMPTY_O)))) {
			sink("[]", 2, writer);
		} else {
			sink("_:", 2, writer);
			if (writer->bprefix && !strncmp((const char*)node->buf,
			                                (const char*)writer->bprefix,
			                                writer->bprefix_len)) {
				sink(node->buf + writer->bprefix_len,
				     node->n_bytes - writer->bprefix_len,
				     writer);
			} else {
				sink(node->buf, node->n_bytes, writer);
			}
		}
		break;
	case SERD_CURIE:
		switch (writer->syntax) {
		case SERD_NTRIPLES:
			if (serd_env_expand(writer->env, node, &uri_prefix, &uri_suffix)) {
				fprintf(stderr, "Undefined namespace prefix `%s'\n", node->buf);
				return false;
			}
			sink("<", 1, writer);
			write_text(writer, WRITE_URI, uri_prefix.buf, uri_prefix.len, '>');
			write_text(writer, WRITE_URI, uri_suffix.buf, uri_suffix.len, '>');
			sink(">", 1, writer);
			break;
		case SERD_TURTLE:
			sink(node->buf, node->n_bytes, writer);
		}
		break;
	case SERD_LITERAL:
		if (writer->syntax == SERD_TURTLE && datatype && datatype->buf) {
			const char* type_uri = (const char*)datatype->buf;
			if (!strncmp(type_uri, NS_XSD, sizeof(NS_XSD) - 1) && (
				    !strcmp(type_uri + sizeof(NS_XSD) - 1, "boolean") ||
				    !strcmp(type_uri + sizeof(NS_XSD) - 1, "decimal") ||
				    !strcmp(type_uri + sizeof(NS_XSD) - 1, "integer"))) {
				sink(node->buf, node->n_bytes, writer);
				break;
			}
		}
		if (writer->syntax != SERD_NTRIPLES
		    && (node->flags & (SERD_HAS_NEWLINE|SERD_HAS_QUOTE))) {
			sink("\"\"\"", 3, writer);
			write_text(writer, WRITE_LONG_STRING,
			           node->buf, node->n_bytes, '\0');
			sink("\"\"\"", 3, writer);
		} else {
			sink("\"", 1, writer);
			write_text(writer, WRITE_STRING, node->buf, node->n_bytes, '"');
			sink("\"", 1, writer);
		}
		if (lang && lang->buf) {
			sink("@", 1, writer);
			sink(lang->buf, lang->n_bytes, writer);
		} else if (datatype && datatype->buf) {
			sink("^^", 2, writer);
			write_node(writer, datatype, NULL, NULL, FIELD_NONE, flags);
		}
		break;
	case SERD_URI:
		if ((writer->syntax == SERD_TURTLE)
		    && !strcmp((const char*)node->buf, NS_RDF "type")) {
			sink("a", 1, writer);
			break;
		} else if ((writer->syntax == SERD_TURTLE)
		           && !strcmp((const char*)node->buf, NS_RDF "nil")) {
			sink("()", 2, writer);
			break;
		} else if ((writer->style & SERD_STYLE_CURIED)
		           && serd_uri_string_has_scheme(node->buf)) {
			SerdNode  prefix;
			SerdChunk suffix;
			if (serd_env_qualify(writer->env, node, &prefix, &suffix)) {
				write_text(writer, WRITE_URI, prefix.buf, prefix.n_bytes, '>');
				sink(":", 1, writer);
				write_text(writer, WRITE_URI, suffix.buf, suffix.len, '>');
				break;
			}
		} else if ((writer->style & SERD_STYLE_RESOLVED)
		           && !serd_uri_string_has_scheme(node->buf)) {
			SerdURI uri;
			serd_uri_parse(node->buf, &uri);
			SerdURI abs_uri;
			serd_uri_resolve(&uri, &writer->base_uri, &abs_uri);
			sink("<", 1, writer);
			serd_uri_serialise(&abs_uri, (SerdSink)sink, writer);
			sink(">", 1, writer);
			break;
		}
		sink("<", 1, writer);
		write_text(writer, WRITE_URI, node->buf, node->n_bytes, '>');
		sink(">", 1, writer);
	default:
		break;
	}
	writer->last_sep = SEP_NONE;
	return true;
}

static inline bool
is_resource(const SerdNode* node)
{
	return node->type > SERD_LITERAL;
}

static void
write_pred(SerdWriter* writer, SerdStatementFlags flags, const SerdNode* pred)
{
	write_node(writer, pred, NULL, NULL, FIELD_PREDICATE, flags);
	write_sep(writer, SEP_P_O);
	copy_node(&writer->context.predicate, pred);
}

static bool
write_list_obj(SerdWriter*        writer,
               SerdStatementFlags flags,
               const SerdNode*    predicate,
               const SerdNode*    object,
               const SerdNode*    datatype,
               const SerdNode*    lang)
{
	if (!strcmp((const char*)object->buf, NS_RDF "nil")) {
		--writer->indent;
		write_sep(writer, SEP_LIST_END);
		return true;
	} else if (!strcmp((const char*)predicate->buf, NS_RDF "first")) {
		write_sep(writer, SEP_LIST_SEP);
		write_node(writer, object, datatype, lang, FIELD_OBJECT, flags);
	}
	return false;
}

SERD_API
SerdStatus
serd_writer_write_statement(SerdWriter*        writer,
                            SerdStatementFlags flags,
                            const SerdNode*    graph,
                            const SerdNode*    subject,
                            const SerdNode*    predicate,
                            const SerdNode*    object,
                            const SerdNode*    datatype,
                            const SerdNode*    lang)
{
	if (!subject || !predicate || !object
	    || !subject->buf || !predicate->buf || !object->buf
	    || !is_resource(subject) || !is_resource(predicate)) {
		return SERD_ERR_BAD_ARG;
	}

	switch (writer->syntax) {
	case SERD_NTRIPLES:
		write_node(writer, subject, NULL, NULL, FIELD_SUBJECT, flags);
		sink(" ", 1, writer);
		write_node(writer, predicate, NULL, NULL, FIELD_PREDICATE, flags);
		sink(" ", 1, writer);
		if (!write_node(writer, object, datatype, lang, FIELD_OBJECT, flags)) {
			return SERD_ERR_UNKNOWN;
		}
		sink(" .\n", 3, writer);
		return SERD_SUCCESS;
	default:
		break;
	}

	if ((flags & SERD_LIST_CONT)) {
		if (write_list_obj(writer, flags, predicate, object, datatype, lang)) {
			// Reached end of list
			if (--writer->list_depth == 0 && writer->list_subj.type) {
				reset_context(writer, true);
				writer->context.subject = writer->list_subj;
				writer->list_subj       = SERD_NODE_NULL;
			}
			return SERD_SUCCESS;
		}
	} else if (serd_node_equals(subject, &writer->context.subject)) {
		if (serd_node_equals(predicate, &writer->context.predicate)) {
			// Abbreviate S P
			if (!(flags & SERD_ANON_O_BEGIN)) {
				++writer->indent;
			}
			write_sep(writer, SEP_END_O);
			write_node(writer, object, datatype, lang, FIELD_OBJECT, flags);
			if (!(flags & SERD_ANON_O_BEGIN)) {
				--writer->indent;
			}
		} else {
			// Abbreviate S
			Sep sep = writer->context.predicate.type ? SEP_END_P : SEP_S_P;
			write_sep(writer, sep);
			write_pred(writer, flags, predicate);
			write_node(writer, object, datatype, lang, FIELD_OBJECT, flags);
		}
	} else {
		// No abbreviation
		if (writer->context.subject.type) {
			assert(writer->indent > 0);
			--writer->indent;
			if (serd_stack_is_empty(&writer->anon_stack)) {
				write_sep(writer, SEP_END_S);
			}
		} else if (!writer->empty) {
			write_sep(writer, SEP_S_P);
		}

		if (!(flags & SERD_ANON_CONT)) {
			write_node(writer, subject, NULL, NULL, FIELD_SUBJECT, flags);
			++writer->indent;
			write_sep(writer, SEP_S_P);
		} else {
			++writer->indent;
		}

		reset_context(writer, true);
		copy_node(&writer->context.subject, subject);

		if (!(flags & SERD_LIST_S_BEGIN)) {
			write_pred(writer, flags, predicate);
		}

		write_node(writer, object, datatype, lang, FIELD_OBJECT, flags);
	}

	if (flags & (SERD_ANON_S_BEGIN|SERD_ANON_O_BEGIN)) {
		WriteContext* ctx = (WriteContext*)serd_stack_push(
			&writer->anon_stack, sizeof(WriteContext));
		*ctx = writer->context;
		WriteContext new_context = {
			serd_node_copy(graph), serd_node_copy(subject), SERD_NODE_NULL };
		if ((flags & SERD_ANON_S_BEGIN)) {
			new_context.predicate = serd_node_copy(predicate);
		}
		writer->context = new_context;
	} else {
		copy_node(&writer->context.graph, graph);
		copy_node(&writer->context.subject, subject);
		copy_node(&writer->context.predicate, predicate);
	}

	return SERD_SUCCESS;
}

SERD_API
SerdStatus
serd_writer_end_anon(SerdWriter*     writer,
                     const SerdNode* node)
{
	if (writer->syntax == SERD_NTRIPLES) {
		return SERD_SUCCESS;
	}
	if (serd_stack_is_empty(&writer->anon_stack)) {
		fprintf(stderr, "Unexpected end of anonymous node\n");
		return SERD_ERR_UNKNOWN;
	}
	assert(writer->indent > 0);
	--writer->indent;
	write_sep(writer, SEP_END_P);
	write_sep(writer, SEP_ANON_END);
	reset_context(writer, true);
	writer->context = *anon_stack_top(writer);
	serd_stack_pop(&writer->anon_stack, sizeof(WriteContext));
	const bool is_subject = serd_node_equals(node, &writer->context.subject);
	if (is_subject) {
		copy_node(&writer->context.subject, node);
		writer->context.predicate.type = SERD_NOTHING;
	}
	return SERD_SUCCESS;
}

SERD_API
SerdStatus
serd_writer_finish(SerdWriter* writer)
{
	if (writer->context.subject.type) {
		sink(" .\n", 3, writer);
	}
	if (writer->style & SERD_STYLE_BULK) {
		serd_bulk_sink_flush(&writer->bulk_sink);
	}
	return reset_context(writer, true);
}

SERD_API
SerdWriter*
serd_writer_new(SerdSyntax     syntax,
                SerdStyle      style,
                SerdEnv*       env,
                const SerdURI* base_uri,
                SerdSink       sink,
                void*          stream)
{
	const WriteContext context = WRITE_CONTEXT_NULL;
	SerdWriter*        writer  = (SerdWriter*)malloc(sizeof(SerdWriter));
	writer->syntax      = syntax;
	writer->style       = style;
	writer->env         = env;
	writer->base_uri    = base_uri ? *base_uri : SERD_URI_NULL;
	writer->anon_stack  = serd_stack_new(sizeof(WriteContext));
	writer->sink        = sink;
	writer->stream      = stream;
	writer->context     = context;
	writer->list_subj   = SERD_NODE_NULL;
	writer->list_depth  = 0;
	writer->bprefix     = NULL;
	writer->bprefix_len = 0;
	writer->indent      = 0;
	writer->last_sep    = SEP_NONE;
	writer->empty       = true;
	if (style & SERD_STYLE_BULK) {
		writer->bulk_sink = serd_bulk_sink_new(sink, stream, SERD_PAGE_SIZE);
	}
	return writer;
}

SERD_API
void
serd_writer_chop_blank_prefix(SerdWriter*    writer,
                              const uint8_t* prefix)
{
	free(writer->bprefix);
	writer->bprefix_len = 0;
	writer->bprefix     = NULL;
	if (prefix) {
		writer->bprefix_len = strlen((const char*)prefix);
		writer->bprefix     = (uint8_t*)malloc(writer->bprefix_len + 1);
		memcpy(writer->bprefix, prefix, writer->bprefix_len + 1);
	}
}

SERD_API
SerdStatus
serd_writer_set_base_uri(SerdWriter*     writer,
                         const SerdNode* uri)
{
	if (!serd_env_set_base_uri(writer->env, uri)) {
		serd_env_get_base_uri(writer->env, &writer->base_uri);

		if (writer->syntax != SERD_NTRIPLES) {
			if (writer->context.graph.type || writer->context.subject.type) {
				sink(" .\n\n", 4, writer);
				reset_context(writer, false);
			}
			sink("@base <", 7, writer);
			sink(uri->buf, uri->n_bytes, writer);
			sink("> .\n", 4, writer);
		}
		return reset_context(writer, false);
	}
	return SERD_ERR_UNKNOWN;
}

SERD_API
SerdStatus
serd_writer_set_prefix(SerdWriter*     writer,
                       const SerdNode* name,
                       const SerdNode* uri)
{
	if (!serd_env_set_prefix(writer->env, name, uri)) {
		if (writer->syntax != SERD_NTRIPLES) {
			if (writer->context.graph.type || writer->context.subject.type) {
				sink(" .\n\n", 4, writer);
				reset_context(writer, false);
			}
			sink("@prefix ", 8, writer);
			sink(name->buf, name->n_bytes, writer);
			sink(": <", 3, writer);
			write_text(writer, WRITE_URI, uri->buf, uri->n_bytes, '>');
			sink("> .\n", 4, writer);
		}
		return reset_context(writer, false);
	}
	return SERD_ERR_UNKNOWN;
}

SERD_API
void
serd_writer_free(SerdWriter* writer)
{
	serd_writer_finish(writer);
	serd_stack_free(&writer->anon_stack);
	free(writer->bprefix);
	if (writer->style & SERD_STYLE_BULK) {
		serd_bulk_sink_free(&writer->bulk_sink);
	}
	free(writer);
}

SERD_API
size_t
serd_file_sink(const void* buf, size_t len, void* stream)
{
	return fwrite(buf, 1, len, (FILE*)stream);
}
