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

#ifndef _PERLSINK_H
#define _PERLSINK_H

#include "serd.h"

struct serdperl_sink_s {
	SV* callback;
	SerdURI base_uri;
	SerdEnv* env;
};

typedef struct serdperl_sink_s serdperl_sink;

serdperl_sink* new_perlsink ( const SerdURI* base_uri );
void free_perlsink ( serdperl_sink* p );

SerdStatus perlsink_write_statement(serdperl_sink* handle, SerdStatementFlags flags, const SerdNode* graph, const SerdNode* subject, const SerdNode* predicate, const SerdNode* object, const SerdNode* datatype, const SerdNode* lang);
SerdStatus perlsink_set_prefix(serdperl_sink* handle, const SerdNode* name, const SerdNode* uri);
SerdStatus perlsink_set_base_uri(serdperl_sink* handle, const SerdNode* uri);

#endif
