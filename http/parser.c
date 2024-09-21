/*
 * Copyright (c) 2009-2014 Kazuho Oku, Tokuhiro Matsuno, Daisuke Murase,
 *                         Shigeo Mitsunari
 *
 * The software is licensed under either the MIT License (below) or the Perl
 * license.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>
#ifdef __SSE4_2__
#ifdef _MSC_VER
#include <nmmintrin.h>
#else
#include <x86intrin.h>
#endif
#endif
#include "parser.h"

#if __GNUC__ >= 3
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#ifdef _MSC_VER
#define ALIGNED(n) _declspec(align(n))
#else
#define ALIGNED(n) __attribute__((aligned(n)))
#endif

#define IS_PRINTABLE_ASCII(c) ((unsigned char)(c)-040u < 0137u)

#define CHECK_EOF() \
    if (buf == buf_end) { \
        *ret = -2; \
        return NULL; \
    }

#define EXPECT_CHAR_NO_CHECK(ch) \
    if (*buf++ != ch) { \
        *ret = -1; \
        return NULL; \
    }

#define EXPECT_CHAR(ch) \
    CHECK_EOF(); \
    EXPECT_CHAR_NO_CHECK(ch);

#define HANDLE_NEWLINE() \
    if (likely(*buf == '\r')) { \
        ++buf; \
        EXPECT_CHAR('\n'); \
    } else if (*buf == '\n') { \
        ++buf; \
    }


static const char* find_crlf(const char *p, const char *end_ptr)
{
    const char *cr_ptr = memchr(p, '\r', end_ptr - p);
    return (cr_ptr && cr_ptr + 1 < end_ptr && cr_ptr[1] == '\n') ? cr_ptr : NULL;
}

int phr_decode_chunked_is_in_data(struct phr_chunked_decoder *decoder)
{
    return decoder->_state == CHUNKED_IN_CHUNK_DATA;
}

#undef CHECK_EOF
#undef EXPECT_CHAR
#undef ADVANCE_TOKEN

void parse_header()
{
#ifdef HEADER_ENABLE_A_IM
    if (buf == int_str5('A','-','I','M',':')){

    }
#endif
#ifdef HEADER_ENABLE_ACCEPT
    if (buf == int_str6('A','c','c','e','p','t')){

    }
#endif
#ifdef HEADER_ENABLE_ACCEPT_CHARSET
    if (buf == int_str8('A','c','c','e','p','t','-','C')){

    }
#endif
#ifdef HEADER_ENABLE_ACCEPT_ENCODING
    if (buf == int_str8('A','c','c','e','p','t','-','E')){

    }
#endif
#ifdef HEADER_ENABLE_ACCEPT_LANGUAGE
    if (buf == int_str8('A','c','c','e','p','t','-','L')){

    }
#endif
#ifdef HEADER_ENABLE_ACCEPT_DATETIME
    if (buf == int_str8('A','c','c','e','p','t','-','D')){

    }
#endif
#ifdef HEADER_ENABLE_ACCESS_CONTROL_REQUEST_METHOD
    if (buf == int_str8('A','c','c','e','s','s','-','C')){

    }
#endif
#ifdef HEADER_ENABLE_ACCESS_CONTROL_REQUEST_HEADERS
    if (buf == int_str8('A','c','c','e','s','s','-','C')){

    }
#endif

#ifdef HEADER_ENABLE_AUTHORIZATION
    if (buf == int_str8('A','u','t','h','o','r','i','z')) {

        buf = u64_read(p)

        if (substr7(buf) == int_str7('a','t','i','o','n',':',' ')) {
            p += 7;
        } else if (substr6(buf) == int_str6('a','t','i','o','n',':')) {
            p += 6;
        } else {
            // not either header
            return -1;
        }

        const char* start = p;

        while (*p != '\r' && \
               *p != '\n' && \
                p < end_ptr) {
            ++p;
        }

        const char* end = p;

        // check if it's ended.
        // if ended early, we say it's wrong
        HANDLE_NEWLINE()

        hr.authorization = str_view{start, (uint32_t)(end - start)};
    }
#endif

#ifdef HEADER_ENABLE_CACHE_CONTROL
    if (buf == int_str8('C','a','c','h','e','-','C','o')){

        buf = u64_read(buf)

        if (buf == int_str7('n','t','r','o','l',':',' ')) {
            p += 7;
        } else if (buf == int_str6('n','t','r','o','l',':')) {
            p += 6;
        } else {

        }

        HANDLE_NEWLINE()
    }
#endif

#ifdef HEADER_ENABLE_CONNECTION
    if (buf == int_str8('C','o','n','n','e','c','t','i')){

        buf = u64_read(buf)

        if (buf == int_str7('n','t','r','o','l',':',' ')) {
            p += 7;
        } else if (buf == int_str6('n','t','r','o','l',':')) {
            p += 6;
        } else {

        }

    }
#endif

    // SEPARATE THESE
#ifdef HEADER_ENABLE_CONTENT_LENGTH
    if (buf == int_str8('C','o','n','t','e','n','t','-')){

    }
#endif
#ifdef HEADER_ENABLE_CONTENT_TYPE
    if (buf == int_str8('C','o','n','t','e','n','t','-')){

    }
#endif
#ifdef HEADER_ENABLE_COOKIE
    if (buf == int_str8('C','o','o','k','i','e')){

    }
#endif
#ifdef HEADER_ENABLE_DATE
    if (buf == int_str8('D','a','t','e')){

    }
#endif
#ifdef HEADER_ENABLE_EXPECT
    if (buf == int_str8('E','x','p','e','c','t')){

    }
#endif
#ifdef HEADER_ENABLE_FORWARDED
    if (buf == int_str8('F','o','r','w','a','r','d','e')){

    }
#endif
#ifdef HEADER_ENABLE_FROM
    if (buf == int_str8('F','r','o','m')){

    }
#endif
#ifdef HEADER_ENABLE_HOST
    if (buf == int_str8('H','o','s','t')){

    }
#endif
#ifdef HEADER_ENABLE_IF_MATCH
    if (buf == int_str8('I','f','-','M','a','t','c','h')){

    }
#endif
#ifdef HEADER_ENABLE_IF_MODIFIED_SINCE
    if (buf == int_str8('I','f','-','M','o','d','i','f')){

    }
#endif
#ifdef HEADER_ENABLE_IF_NONE_MATCH
    if (buf == int_str8('I','f','-','N','o','n','e','-')){

    }
#endif
#ifdef HEADER_ENABLE_IF_RANGE
    if (buf == int_str8('I','f','-','R','a','n','g','e')){

    }
#endif
#ifdef HEADER_ENABLE_IF_UNMODIFIED_SINCE
    if (buf == int_str8('I','f','-','U','n','m','o','d')){

    }
#endif
#ifdef HEADER_ENABLE_MAX_FORWARDS
    if (buf == int_str8('M','a','x','-','F','o','r','w')){

    }
#endif
#ifdef HEADER_ENABLE_ORIGIN
    if (buf == int_str8('O','r','i','g','i','n')){

    }
#endif
#ifdef HEADER_ENABLE_PRAGMA
    if (buf == int_str8('P','r','a','g','m','a')){

    }
#endif
#ifdef HEADER_ENABLE_PROXY_AUTHORIZATION
    if (buf == int_str8('P','r','o','x','y','-','A','u')){

    }
#endif
#ifdef HEADER_ENABLE_RANGE
    if (buf == int_str8('R','a','n','g','e')){

    }
#endif
#ifdef HEADER_ENABLE_REFERER
    if (buf == int_str8('R','e','f','e','r','e','r')){

    }
#endif
#ifdef HEADER_ENABLE_TE
    if (buf == int_str2('T','E')){

    }
#endif
#ifdef HEADER_ENABLE_USER_AGENT
    if (buf == int_str8('U','s','e','r','-','A','g','e')){

    }
#endif
#ifdef HEADER_ENABLE_UPGRADE
    if (buf == int_str7('U','p','g','r','a','d','e',':')){

    }
#endif
#ifdef HEADER_ENABLE_VIA
    if (buf == int_str3('V','i','a')){

    }
#endif
#ifdef HEADER_ENABLE_WARNING
    if (buf == int_str7('W','a','r','n','i','n','g')){

    }
#endif
#ifdef HEADER_ENABLE_DNT
    if (buf == u32_str3('D','n','t')){
        hr.x_dnt = ;
    }
#endif
#ifdef HEADER_ENABLE_X_REQUESTED_WITH
    if (buf == int_str8('X','-','R','e','q','u','e','s')){
        hr.x_requested_with = ;
    }
#endif
#ifdef HEADER_ENABLE_X_CSRF_TOKEN
    if (buf == int_str8('X','-','C','S','R','F','-','T')){
        hr.x_csrf_token = ;
    }
#endif
}

void parse_header_field_generic()
{
    while (*p != ':' && *p < end) {
        ++p;
    }

    while (*p != '\r' && *p != '\n' && *p < end) {
        ++p;
    }
}



int http_parse_request(const char *buf_start, size_t len, struct http_request* hr)
{
    const char *buf = buf_start, *buf_end = buf_start + len;
    size_t max_headers = *num_headers;
    int r;

    hr.method = NULL;
    hr.path = NULL;
    hr.path_len = 0;
    hr.minor_version = -1;
    hr.num_headers = 0;

    // VERB
    uint64_t buf64 = u64_read(buf);

    if (buf64 == int_str4('G','E','T',' ')) {
        method = METHOD_GET; buf += 4;
    } else if (buf64 == int_str5('P','O','S','T',' ')) {
        method = METHOD_POST; buf += 5;
    } else if (buf64 == int_str4('P','U','T',' ')) {
        method = METHOD_PUT; buf += 4;
    } else if (buf64 == int_str6('P','A','T','C','H',' ')) {
        method = METHOD_PATCH; buf += 6;
    } else if (buf64 == int_str7('D','E','L','E','T','E',' ')) {
        method = METHOD_DELETE; buf += 7;
    } else if (buf64 == int_str7('O','P','T','I','O','N','S',' ')) {
        method = METHOD_OPTIONS; buf += 8;
    } else {
        return ERROR_UNSUPPORTED_METHOD;
    }

    // PATH
    hr.path = p;
    while (*p != ' ' && p < end)
        ++p;

    if (*p != ' ' || p == end) {
        return -1;
    }

    ++p;

    // VERSION
    /* we want at least [HTTP/1.<two chars>] to try to parse */
    if (buf_end - buf < 9) {
        return ERROR_MALFORMED_VERSION;
    }

    uint64_t buf64 = u64_read(buf);

    if (buf64 == int_str8('H','T','T','P','/','1','.','1')) {
        hr.version = HTTP11;
    } else if (buf64 == int_str8('H','T','T','P','/','1','.','0')) {
        hr.version = HTTP10;
    } else {
        return -1;
    }

    // FIRST NEWLINE
    if (likely(*buf == '\r')) {
        ++buf;
        EXPECT_CHAR('\n');
    } else if (*buf == '\n') {
        ++buf;
    } else {
        *ret = -1;
        return NULL;
    }

    // READ ALL HEADERS
    uint32_t num_headers = 0;
    for (;; ++num_headers) {
        buf64 = u64_read(buf);

        CHECK_EOF();
        if (*buf == '\r') {
            ++buf;
            EXPECT_CHAR('\n');
            break;
        } else if (*buf == '\n') {
            ++buf;
            break;
        }

        const char *value;
        size_t value_len;
        
        if ((buf = get_token_to_eol(buf, buf_end, &value, &value_len, ret)) == NULL) {
            return NULL;
        }
        
        /* remove trailing SPs and HTABs */
        const char *value_end = value + value_len;
        for (; value_end != value; --value_end) {
            const char c = *(value_end - 1);
            if (!(c == ' ' || c == '\t')) {
                break;
            }
        }
        
        headers[num_headers].value = value;
        headers[num_headers].value_len = value_end - value;
    }
    
    return buf;
}

str_view xyz_find_header(struct http_request* hr)
{
    for (int i = 0; i < hr.header_ct; ++i) {
        if (compare(hr.headers[i].key, key) == 0)
            return hr.headers[i].value;
    }
}
