#ifndef picohttpparser_h
#define picohttpparser_h

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* contains name and value of a header (name == NULL if is a continuing line
 * of a multiline header */
struct header_kv
{
    str_view key;
    str_view value;
};

struct str_view
{
    const char *value;
    size_t value_len;
};

struct http_request
{
    const uint32_t version;
    const uint32_t method;
    uint32_t connection;
    uint32_t headers;
    uint32_t last_len;

    /*
    ** Default header kv-pairs, usually too common
    ** to treat in the same way as a standard header.
    */
    struct str_view path;
    struct str_view user_agent;
    struct str_view accept_language;
    struct str_view accept_encoding;
    struct str_view accept;
    struct str_view referrer;
    struct str_view authorization;
    struct str_view upgrade;
    struct header_kv* headers;
};

/* returns number of bytes consumed if successful, -2 if request is partial,
 * -1 if failed */
// parse http request
int phr_parse_request(const char *buf, size_t len, const char **method, size_t *method_len, const char **path, size_t *path_len,
                      int *minor_version, struct header_kv *headers, size_t *num_headers, size_t last_len);

int phr_parse_request(const char *buf, size_t len, struct http_request* hr, struct header_kv* headers);

int phr_parse_response(const char *_buf, size_t len, int *minor_version, int *status, const char **msg, size_t *msg_len,
                       struct header_kv *headers, size_t *num_headers, size_t last_len);

int phr_parse_headers(const char *buf, size_t len, struct header_kv *headers, size_t *num_headers, size_t last_len);

/* should be zero-filled before start */
struct phr_chunked_decoder {
    size_t bytes_left_in_chunk; /* number of bytes left in current chunk */
    char consume_trailer;       /* if trailing headers should be consumed */
    char _hex_count;
    char _state;
};

/* the function rewrites the buffer given as (buf, bufsz) removing the chunked-
 * encoding headers.  When the function returns without an error, bufsz is
 * updated to the length of the decoded data available.  Applications should
 * repeatedly call the function while it returns -2 (incomplete) every time
 * supplying newly arrived data.  If the end of the chunked-encoded data is
 * found, the function returns a non-negative number indicating the number of
 * octets left undecoded, that starts from the offset returned by `*bufsz`.
 * Returns -1 on error.
 */
ssize_t phr_decode_chunked(struct phr_chunked_decoder *decoder, char *buf, size_t *bufsz);

/* returns if the chunked decoder is in middle of chunked data */
int phr_decode_chunked_is_in_data(struct phr_chunked_decoder *decoder);

#ifdef __cplusplus
}
#endif

#endif