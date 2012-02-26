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

#include "serd_internal.h"
#include "perlsink.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int serdperl_parse_string ( serdperl_sink* handle, const uint8_t* string, const uint8_t* base_uri_str ) {
	SerdURI  base_uri = SERD_URI_NULL;
	SerdNode base_uri_node = serd_node_new_uri_from_string(base_uri_str, &base_uri, &base_uri);
	SerdEnv* env    = serd_env_new(&base_uri_node);
	
	SerdReader* reader = serd_reader_new(
										 SERD_TURTLE, handle, NULL,
										 (SerdBaseSink)perlsink_set_base_uri,
										 (SerdPrefixSink)perlsink_set_prefix,
										 (SerdStatementSink)perlsink_write_statement,
										 (SerdEndSink)NULL);
	
	const SerdStatus status = serd_reader_read_string(reader, string);
	if (status) {}
	serd_reader_free(reader);
	free_perlsink(handle);
	serd_node_free(&base_uri_node);
	return 0;
}

static int serdperl_parse_file ( serdperl_sink* handle, const uint8_t* filename, const uint8_t* base_uri_str ) {
	FILE* in_fd;
	const uint8_t* input = serd_uri_to_path(filename);
	if (!input || !(in_fd = serd_fopen((const char*)input, "r"))) {
		return 1;
	}
	SerdURI  base_uri = SERD_URI_NULL;
	SerdNode base_uri_node = serd_node_new_uri_from_string(base_uri_str, &base_uri, &base_uri);
	SerdEnv* env    = serd_env_new(&base_uri_node);
	
	SerdReader* reader = serd_reader_new(
										 SERD_TURTLE, handle, NULL,
										 (SerdBaseSink)perlsink_set_base_uri,
										 (SerdPrefixSink)perlsink_set_prefix,
										 (SerdStatementSink)perlsink_write_statement,
										 (SerdEndSink)NULL);
	
	const SerdStatus status = serd_reader_read_file_handle(reader, in_fd, filename);
	if (status) {}
//	const SerdStatus status = serd_reader_read_string(reader, input);
	serd_reader_free(reader);
	fclose(in_fd);
	serd_node_free(&base_uri_node);
	return 0;
}

int main(int argc, char** argv) {
	bool           from_file     = true;
	const uint8_t* in_name       = NULL;
	int            a             = 1;
	for (; a < argc && argv[a][0] == '-'; ++a) {
		if (argv[a][1] == 's') {
			in_name = (const uint8_t*)"(string)";
			from_file = false;
			++a;
			break;
		} else {
			fprintf(stderr, "%s: Unknown option `%s'\n", argv[0], argv[a]);
		}
	}

	if (a == argc) {
		fprintf(stderr, "%s: Missing input\n", argv[0]);
		return 1;
	}
	
	const uint8_t* input = (const uint8_t*)argv[a++];
	const uint8_t* base_uri_str = NULL;
	if (a < argc) {  // Base URI given on command line
		base_uri_str = (const uint8_t*)argv[a];
	} else if (from_file) {  // Use input file URI
		base_uri_str = input;
	} else {
		base_uri_str = (const uint8_t*)"";
	}
	
	serdperl_sink* handle	= new_perlsink(NULL, "STATEMENT");
	if (from_file) {
		parse_file(handle, input, base_uri_str);
	} else {
		parse_string(handle, input, base_uri_str);
	}
	free_perlsink(handle);
	return 0;
}
