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

#define CHECK_EOF()                                                                                                                \
    if (buf == buf_end) {                                                                                                          \
        *ret = -2;                                                                                                                 \
        return NULL;                                                                                                               \
    }

#define EXPECT_CHAR_NO_CHECK(ch)                                                                                                   \
    if (*buf++ != ch) {                                                                                                            \
        *ret = -1;                                                                                                                 \
        return NULL;                                                                                                               \
    }

#define EXPECT_CHAR(ch)                                                                                                            \
    CHECK_EOF();                                                                                                                   \
    EXPECT_CHAR_NO_CHECK(ch);

#define HANDLE_NEWLINE()
    if (likely(*buf == '\r')) {
        ++buf;
        EXPECT_CHAR('\n');
    } else if (*buf == '\n') {
        ++buf;
    }




#define ADVANCE_TOKEN(tok, toklen)                                                                                                 \
    do {                                                                                                                           \
        const char *tok_start = buf;                                                                                               \
        static const char ALIGNED(16) ranges2[16] = "\000\040\177\177";                                                            \
        int found2;                                                                                                                \
        buf = findchar_fast(buf, buf_end, ranges2, 4, &found2);                                                                    \
        if (!found2) {                                                                                                             \
            CHECK_EOF();                                                                                                           \
        }                                                                                                                          \
        while (1) {                                                                                                                \
            if (*buf == ' ') {                                                                                                     \
                break;                                                                                                             \
            } else if (unlikely(!IS_PRINTABLE_ASCII(*buf))) {                                                                      \
                if ((unsigned char)*buf < '\040' || *buf == '\177') {  /* < ' ' || * == 127*/                                      \
                    *ret = -1;                                                                                                     \
                    return NULL;                                                                                                   \
                }                                                                                                                  \
            }                                                                                                                      \
            ++buf;                                                                                                                 \
            CHECK_EOF();                                                                                                           \
        }                                                                                                                          \
        tok = tok_start;                                                                                                           \
        toklen = buf - tok_start;                                                                                                  \
    } while (0)

static const char *token_char_map = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                    "\0\1\0\1\1\1\1\1\0\0\1\1\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0"
                                    "\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\1\1"
                                    "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\1\0\1\0"
                                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static const char *findchar_fast(const char *buf, const char *buf_end, const char *ranges, size_t ranges_size, int *found)
{
    *found = 0;
#if __SSE4_2__
    if (likely(buf_end - buf >= 16)) {
        __m128i ranges16 = _mm_loadu_si128((const __m128i *)ranges);

        size_t left = (buf_end - buf) & ~15;
        do {
            __m128i b16 = _mm_loadu_si128((const __m128i *)buf);
            int r = _mm_cmpestri(ranges16, ranges_size, b16, 16, _SIDD_LEAST_SIGNIFICANT | _SIDD_CMP_RANGES | _SIDD_UBYTE_OPS);
            if (unlikely(r != 16)) {
                buf += r;
                *found = 1;
                break;
            }
            buf += 16;
            left -= 16;
        } while (likely(left != 0));
    }
#else
    /* suppress unused parameter warning */
    (void)buf_end;
    (void)ranges;
    (void)ranges_size;
#endif
    return buf;
}

static const char *get_token_to_eol(const char *buf, const char *buf_end, const char **token, size_t *token_len, int *ret)
{
    const char *token_start = buf;

#ifdef __SSE4_2__
    static const char ALIGNED(16) ranges1[16] = "\0\010"    /* allow HT */
                                                "\012\037"  /* allow SP and up to but not including DEL */
                                                "\177\177"; /* allow chars w. MSB set */
    int found;
    buf = findchar_fast(buf, buf_end, ranges1, 6, &found);
    if (found)
        goto FOUND_CTL;
#else
    /* find non-printable char within the next 8 bytes, this is the hottest code; manually inlined */
    while (likely(buf_end - buf >= 8)) {
#define DOIT()                                                                                                                     \
    do {                                                                                                                           \
        if (unlikely(!IS_PRINTABLE_ASCII(*buf)))                                                                                   \
            goto NonPrintable;                                                                                                     \
        ++buf;                                                                                                                     \
    } while (0)
        DOIT();
        DOIT();
        DOIT();
        DOIT();
        DOIT();
        DOIT();
        DOIT();
        DOIT();
#undef DOIT
        continue;
    NonPrintable:
        if ((likely((unsigned char)*buf < '\040') && likely(*buf != '\011')) || unlikely(*buf == '\177')) {
            goto FOUND_CTL;
        }
        ++buf;
    }
#endif
    for (;; ++buf) {
        CHECK_EOF();
        if (unlikely(!IS_PRINTABLE_ASCII(*buf))) {
            if ((likely((unsigned char)*buf < '\040') && likely(*buf != '\011')) || unlikely(*buf == '\177')) {
                goto FOUND_CTL;
            }
        }
    }
FOUND_CTL:
    if (likely(*buf == '\r')) {
        ++buf;
        EXPECT_CHAR('\n');
        *token_len = buf - 2 - token_start;
    } else if (*buf == '\n') {
        *token_len = buf - token_start;
        ++buf;
    } else {
        *ret = -1;
        return NULL;
    }
    *token = token_start;

    return buf;
}

static const char *is_complete(const char *buf, const char *buf_end, size_t last_len, int *ret)
{
    int ret_cnt = 0;
    buf = last_len < 3 ? buf : buf + last_len - 3;

    while (1) {
        CHECK_EOF();
        if (*buf == '\r') {
            ++buf;
            CHECK_EOF();
            EXPECT_CHAR('\n');
            ++ret_cnt;
        } else if (*buf == '\n') {
            ++buf;
            ++ret_cnt;
        } else {
            ++buf;
            ret_cnt = 0;
        }
        if (ret_cnt == 2) {
            return buf;
        }
    }

    *ret = -2;
    return NULL;
}

#define PARSE_INT(valp_, mul_)                                                                                                     \
    if (*buf < '0' || '9' < *buf) {                                                                                                \
        buf++;                                                                                                                     \
        *ret = -1;                                                                                                                 \
        return NULL;                                                                                                               \
    }                                                                                                                              \
    *(valp_) = (mul_) * (*buf++ - '0');

#define PARSE_INT_3(valp_)                                                                                                         \
    do {                                                                                                                           \
        int res_ = 0;                                                                                                              \
        PARSE_INT(&res_, 100)                                                                                                      \
        *valp_ = res_;                                                                                                             \
        PARSE_INT(&res_, 10)                                                                                                       \
        *valp_ += res_;                                                                                                            \
        PARSE_INT(&res_, 1)                                                                                                        \
        *valp_ += res_;                                                                                                            \
    } while (0)

/* returned pointer is always within [buf, buf_end), or null */
static const char *parse_token(const char *buf, const char *buf_end, const char **token, size_t *token_len, char next_char,
                               int *ret)
{
    /* We use pcmpestri to detect non-token characters. This instruction can take no more than eight character ranges (8*2*8=128
     * bits that is the size of a SSE register). Due to this restriction, characters `|` and `~` are handled in the slow loop. */
    static const char ALIGNED(16) ranges[] = "\x00 "  /* control chars and up to SP */
                                             "\"\""   /* 0x22 */
                                             "()"     /* 0x28,0x29 */
                                             ",,"     /* 0x2c */
                                             "//"     /* 0x2f */
                                             ":@"     /* 0x3a-0x40 */
                                             "[]"     /* 0x5b-0x5d */
                                             "{\xff"; /* 0x7b-0xff */
    const char *buf_start = buf;
    int found;
    buf = findchar_fast(buf, buf_end, ranges, sizeof(ranges) - 1, &found);
    if (!found) {
        CHECK_EOF();
    }
    while (1) {
        if (*buf == next_char) {
            break;
        } else if (!token_char_map[(unsigned char)*buf]) {
            *ret = -1;
            return NULL;
        }
        ++buf;
        CHECK_EOF();
    }
    *token = buf_start;
    *token_len = buf - buf_start;
    return buf;
}

/* returned pointer is always within [buf, buf_end), or null */
static const char *parse_http_version(const char *buf, const char *buf_end, int *minor_version, int *ret)
{
    /* we want at least [HTTP/1.<two chars>] to try to parse */
    if (buf_end - buf < 9) {
        *ret = -2;
        return NULL;
    }
    if (memcmp(buf, "HTTP/1.", 7) == 0) {

    }

    if (*buf - '0')
        return buf;
    //PARSE_INT(minor_version, 1);
    return buf;
}

static const char *parse_headers(const char *buf, const char *buf_end, struct phr_header *headers, size_t *num_headers,
                                 size_t max_headers, int *ret)
{
    for (;; ++*num_headers) {
        CHECK_EOF();
        if (*buf == '\r') {
            ++buf;
            EXPECT_CHAR('\n');
            break;
        } else if (*buf == '\n') {
            ++buf;
            break;
        }

        if (*num_headers == max_headers) {
            *ret = -1;
            return NULL;
        }

        if (!(*num_headers != 0 && (*buf == ' ' || *buf == '\t'))) {
            /* parsing name, but do not discard SP before colon, see
             * http://www.mozilla.org/security/announce/2006/mfsa2006-33.html */
            if ((buf = parse_token(buf, buf_end, &headers[*num_headers].name, &headers[*num_headers].name_len, ':', ret)) == NULL) {
                return NULL;
            }
            if (headers[*num_headers].name_len == 0) {
                *ret = -1;
                return NULL;
            }
            ++buf;
            for (;; ++buf) {
                CHECK_EOF();
                if (!(*buf == ' ' || *buf == '\t')) {
                    break;
                }
            }
        } else {
            headers[*num_headers].name = NULL;
            headers[*num_headers].name_len = 0;
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
        headers[*num_headers].value = value;
        headers[*num_headers].value_len = value_end - value;
    }
    return buf;
}

static const char *parse_request(const char *buf, const char *buf_end, const char **method, size_t *method_len, const char **path,
                                 size_t *path_len, int *minor_version, struct phr_header *headers, size_t *num_headers,
                                 size_t max_headers, int *ret)
{
    /* skip first empty line (some clients add CRLF after POST content) */
    CHECK_EOF();
    if (*buf == '\r') {
        ++buf;
        EXPECT_CHAR('\n');
    } else if (*buf == '\n') {
        ++buf;
    }

    /* parse request line */
    if ((buf = parse_token(buf, buf_end, method, method_len, ' ', ret)) == NULL) {
        return NULL;
    }
    do {
        ++buf;
        CHECK_EOF();
    } while (*buf == ' ');
    ADVANCE_TOKEN(*path, *path_len);
    do {
        ++buf;
        CHECK_EOF();
    } while (*buf == ' ');
    if (*method_len == 0 || *path_len == 0) {
        *ret = -1;
        return NULL;
    }
    if ((buf = parse_http_version(buf, buf_end, minor_version, ret)) == NULL) {
        return NULL;
    }
    if (*buf == '\015') {
        ++buf;
        EXPECT_CHAR('\012');
    } else if (*buf == '\012') {
        ++buf;
    } else {
        *ret = -1;
        return NULL;
    }

    return parse_headers(buf, buf_end, headers, num_headers, max_headers, ret);
}

static const char *parse_response(const char *buf, const char *buf_end, int *minor_version, int *status, const char **msg,
                                  size_t *msg_len, struct phr_header *headers, size_t *num_headers, size_t max_headers, int *ret)
{
    /* parse "HTTP/1.x" */
    if ((buf = parse_http_version(buf, buf_end, minor_version, ret)) == NULL) {
        return NULL;
    }
    /* skip space */
    if (*buf != ' ') {
        *ret = -1;
        return NULL;
    }
    do {
        ++buf;
        CHECK_EOF();
    } while (*buf == ' ');
    /* parse status code, we want at least [:digit:][:digit:][:digit:]<other char> to try to parse */
    if (buf_end - buf < 4) {
        *ret = -2;
        return NULL;
    }
    PARSE_INT_3(status);

    /* get message including preceding space */
    if ((buf = get_token_to_eol(buf, buf_end, msg, msg_len, ret)) == NULL) {
        return NULL;
    }
    if (*msg_len == 0) {
        /* ok */
    } else if (**msg == ' ') {
        /* Remove preceding space. Successful return from `get_token_to_eol` guarantees that we would hit something other than SP
         * before running past the end of the given buffer. */
        do {
            ++*msg;
            --*msg_len;
        } while (**msg == ' ');
    } else {
        /* garbage found after status code */
        *ret = -1;
        return NULL;
    }

    return parse_headers(buf, buf_end, headers, num_headers, max_headers, ret);
}



int phr_parse_response(const char *buf_start, size_t len, int *minor_version, int *status, const char **msg, size_t *msg_len,
                       struct phr_header *headers, size_t *num_headers, size_t last_len)
{
    const char *buf = buf_start, *buf_end = buf + len;
    size_t max_headers = *num_headers;
    int r;

    *minor_version = -1;
    *status = 0;
    *msg = NULL;
    *msg_len = 0;
    *num_headers = 0;

    /* if last_len != 0, check if the response is complete (a fast countermeasure
       against slowloris */
    if (last_len != 0 && is_complete(buf, buf_end, last_len, &r) == NULL) {
        return r;
    }

    if ((buf = parse_response(buf, buf_end, minor_version, status, msg, msg_len, headers, num_headers, max_headers, &r)) == NULL) {
        return r;
    }

    return (int)(buf - buf_start);
}

int phr_parse_headers(const char *buf_start, size_t len, struct phr_header *headers, size_t *num_headers, size_t last_len)
{
    const char *buf = buf_start, *buf_end = buf + len;
    size_t max_headers = *num_headers;
    int r;

    *num_headers = 0;

    /* if last_len != 0, check if the response is complete (a fast countermeasure
       against slowloris */
    if (last_len != 0 && is_complete(buf, buf_end, last_len, &r) == NULL) {
        return r;
    }

    if ((buf = parse_headers(buf, buf_end, headers, num_headers, max_headers, &r)) == NULL) {
        return r;
    }

    return (int)(buf - buf_start);
}

enum {
    CHUNKED_IN_CHUNK_SIZE,
    CHUNKED_IN_CHUNK_EXT,
    CHUNKED_IN_CHUNK_DATA,
    CHUNKED_IN_CHUNK_CRLF,
    CHUNKED_IN_TRAILERS_LINE_HEAD,
    CHUNKED_IN_TRAILERS_LINE_MIDDLE
};

static int decode_hex(int ch)
{
    if ('0' <= ch && ch <= '9') {
        return ch - '0';
    } else if ('A' <= ch && ch <= 'F') {
        return ch - 'A' + 0xa;
    } else if ('a' <= ch && ch <= 'f') {
        return ch - 'a' + 0xa;
    } else {
        return -1;
    }
}

ssize_t phr_decode_chunked(struct phr_chunked_decoder *decoder, char *buf, size_t *_bufsz)
{
    size_t dst = 0, src = 0, bufsz = *_bufsz;
    ssize_t ret = -2; /* incomplete */

    while (1) {
        switch (decoder->_state) {
        case CHUNKED_IN_CHUNK_SIZE:
            for (;; ++src) {
                int v;
                if (src == bufsz)
                    goto Exit;
                if ((v = decode_hex(buf[src])) == -1) {
                    if (decoder->_hex_count == 0) {
                        ret = -1;
                        goto Exit;
                    }
                    break;
                }
                if (decoder->_hex_count == sizeof(size_t) * 2) {
                    ret = -1;
                    goto Exit;
                }
                decoder->bytes_left_in_chunk = decoder->bytes_left_in_chunk * 16 + v;
                ++decoder->_hex_count;
            }
            decoder->_hex_count = 0;
            decoder->_state = CHUNKED_IN_CHUNK_EXT;
        /* fallthru */
        case CHUNKED_IN_CHUNK_EXT:
            /* RFC 7230 A.2 "Line folding in chunk extensions is disallowed" */
            for (;; ++src) {
                if (src == bufsz)
                    goto Exit;
                if (buf[src] == '\012')
                    break;
            }
            ++src;
            if (decoder->bytes_left_in_chunk == 0) {
                if (decoder->consume_trailer) {
                    decoder->_state = CHUNKED_IN_TRAILERS_LINE_HEAD;
                    break;
                } else {
                    goto Complete;
                }
            }
            decoder->_state = CHUNKED_IN_CHUNK_DATA;
        /* fallthru */
        case CHUNKED_IN_CHUNK_DATA: {
            size_t avail = bufsz - src;
            if (avail < decoder->bytes_left_in_chunk) {
                if (dst != src)
                    memmove(buf + dst, buf + src, avail);
                src += avail;
                dst += avail;
                decoder->bytes_left_in_chunk -= avail;
                goto Exit;
            }
            if (dst != src)
                memmove(buf + dst, buf + src, decoder->bytes_left_in_chunk);
            src += decoder->bytes_left_in_chunk;
            dst += decoder->bytes_left_in_chunk;
            decoder->bytes_left_in_chunk = 0;
            decoder->_state = CHUNKED_IN_CHUNK_CRLF;
        }
        /* fallthru */
        case CHUNKED_IN_CHUNK_CRLF:
            for (;; ++src) {
                if (src == bufsz)
                    goto Exit;
                if (buf[src] != '\015')
                    break;
            }
            if (buf[src] != '\012') {
                ret = -1;
                goto Exit;
            }
            ++src;
            decoder->_state = CHUNKED_IN_CHUNK_SIZE;
            break;
        case CHUNKED_IN_TRAILERS_LINE_HEAD:
            for (;; ++src) {
                if (src == bufsz)
                    goto Exit;
                if (buf[src] != '\015')
                    break;
            }
            if (buf[src++] == '\012')
                goto Complete;
            decoder->_state = CHUNKED_IN_TRAILERS_LINE_MIDDLE;
        /* fallthru */
        case CHUNKED_IN_TRAILERS_LINE_MIDDLE:
            for (;; ++src) {
                if (src == bufsz)
                    goto Exit;
                if (buf[src] == '\012')
                    break;
            }
            ++src;
            decoder->_state = CHUNKED_IN_TRAILERS_LINE_HEAD;
            break;
        default:
            assert(!"decoder is corrupt");
        }
    }

Complete:
    ret = bufsz - src;
Exit:
    if (dst != src)
        memmove(buf + dst, buf + src, bufsz - src);
    *_bufsz = dst;
    return ret;
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



int xyz_parse_request(const char *buf_start, size_t len, struct http_request* hr)
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
