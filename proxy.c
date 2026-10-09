/*
 * torrent-proxy.c — announce-rewriting proxy for PornoLab
 *
 * Build (Alpine musl, static):
 *   apk add gcc musl-dev libcurl-dev
 *   gcc -O2 -o proxy proxy.c -lcurl -lpthread
 *
 * GET /dl/<topic_id>   fetch .torrent, rewrite announces, return bytes
 * GET /ann?t=<tok>&…   forward announce with downloaded=0
 * GET /healthz         liveness check
 *
 * Environment:
 *   PORNOLAB_URL       default https://pornolab.net
 *   PORNOLAB_USERNAME
 *   PORNOLAB_PASSWORD
 *   PROXY_SELF_URL     base URL qBittorrent uses to reach this proxy
 *                      default http://127.0.0.1:8008
 *   PROXY_PORT         default 8008
 *   PROXY_DATA_DIR     cookie jar directory, default /config/proxy
 *   PROXY_API_KEY      optional; if set, require ?apikey= or X-Api-Key header
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── config ─────────────────────────────────────────────────────────────── */

static const char *g_base;        /* PORNOLAB_URL   */
static const char *g_user;        /* PORNOLAB_USERNAME */
static const char *g_pass;        /* PORNOLAB_PASSWORD */
static const char *g_self;        /* PROXY_SELF_URL  */
static const char *g_data;        /* PROXY_DATA_DIR  */
static const char *g_apikey;      /* PROXY_API_KEY   */
static int         g_port;        /* PROXY_PORT      */
static char        g_cookiefile[512];

/* ── logging ─────────────────────────────────────────────────────────────── */

static void logf(const char *fmt, ...) {
    time_t t = time(NULL);
    char ts[32]; strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", gmtime(&t));
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "%s proxy ", ts); vfprintf(stderr, fmt, ap); fputc('\n', stderr);
    va_end(ap);
}

/* ── dynamic buffer ──────────────────────────────────────────────────────── */

typedef struct { uint8_t *buf; size_t len, cap; } Buf;

static void buf_grow(Buf *b, size_t need) {
    if (b->len + need <= b->cap) return;
    size_t nc = b->cap ? b->cap * 2 : 4096;
    while (nc < b->len + need) nc *= 2;
    b->buf = realloc(b->buf, nc); b->cap = nc;
}
static void buf_append(Buf *b, const void *data, size_t n) {
    buf_grow(b, n); memcpy(b->buf + b->len, data, n); b->len += n;
}
static void buf_appendz(Buf *b, const char *s) { buf_append(b, s, strlen(s)); }
static size_t curl_write_cb(void *ptr, size_t sz, size_t nmemb, void *ud) {
    buf_append((Buf *)ud, ptr, sz * nmemb); return sz * nmemb;
}

/* ── session (curl with cookie jar) ─────────────────────────────────────── */

static CURL          *g_curl;
static pthread_mutex_t g_curl_mtx = PTHREAD_MUTEX_INITIALIZER;
static int             g_logged_in = 0;

static CURL *make_curl(void) {
    CURL *c = curl_easy_init();
    curl_easy_setopt(c, CURLOPT_USERAGENT,      "Mozilla/5.0");
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION,  1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,         30L);
    curl_easy_setopt(c, CURLOPT_COOKIEJAR,       g_cookiefile);
    curl_easy_setopt(c, CURLOPT_COOKIEFILE,      g_cookiefile);
    return c;
}

/* extract a hidden input value from raw HTML: name="…" value="…" */
static int html_input(const char *html, const char *name,
                      char *out, size_t outsz) {
    /* find name="<name>" */
    char needle[256]; snprintf(needle, sizeof needle, "name=\"%s\"", name);
    const char *p = strcasestr(html, needle);
    if (!p) { *out = 0; return 0; }
    /* scan backwards for the opening < of this <input */
    while (p > html && *p != '<') p--;
    /* now find value=" within the same tag */
    const char *tag_end = strchr(p, '>');
    char tag[4096]; size_t tlen = tag_end ? (size_t)(tag_end - p) : strlen(p);
    if (tlen >= sizeof tag) tlen = sizeof tag - 1;
    memcpy(tag, p, tlen); tag[tlen] = 0;
    const char *vp = strcasestr(tag, "value=\"");
    if (!vp) { *out = 0; return 0; }
    vp += 7;
    const char *ve = strchr(vp, '"');
    size_t vl = ve ? (size_t)(ve - vp) : strlen(vp);
    if (vl >= outsz) vl = outsz - 1;
    memcpy(out, vp, vl); out[vl] = 0;
    return 1;
}

/* find the first input whose name starts with prefix */
static int html_input_prefix(const char *html, const char *prefix,
                              char *nameout, size_t namesz,
                              char *valout,  size_t valsz) {
    const char *p = html;
    while ((p = strcasestr(p, "<input")) != NULL) {
        const char *end = strchr(p, '>');
        size_t tl = end ? (size_t)(end - p) : strlen(p);
        char tag[4096]; if (tl >= sizeof tag) tl = sizeof tag - 1;
        memcpy(tag, p, tl); tag[tl] = 0;
        /* extract name */
        const char *np = strcasestr(tag, "name=\"");
        if (np) {
            np += 6; const char *ne = strchr(np, '"');
            size_t nl = ne ? (size_t)(ne - np) : strlen(np);
            char nm[256]; if (nl >= sizeof nm) nl = sizeof nm - 1;
            memcpy(nm, np, nl); nm[nl] = 0;
            if (strncmp(nm, prefix, strlen(prefix)) == 0) {
                snprintf(nameout, namesz, "%s", nm);
                html_input(html, nm, valout, valsz);
                return 1;
            }
        }
        p++;
    }
    *nameout = 0; *valout = 0; return 0;
}

static char *url_encode(const char *s) {
    return curl_easy_escape(g_curl, s, 0);
}

static int do_login(void) {
    if (!g_user || !*g_user || !g_pass || !*g_pass) {
        logf("ERROR: PORNOLAB_USERNAME / PORNOLAB_PASSWORD not set"); return 0;
    }
    CURL *c = make_curl();
    Buf body = {0};
    char url[1024]; snprintf(url, sizeof url, "%s/forum/login.php", g_base);

    /* fetch login page */
    curl_easy_setopt(c, CURLOPT_URL,            url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,      &body);
    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) { logf("login page fetch: %s", curl_easy_strerror(rc)); goto fail; }

    {
        char html[65536]; size_t hl = body.len < sizeof html - 1 ? body.len : sizeof html - 1;
        memcpy(html, body.buf, hl); html[hl] = 0;

        char cap_sid[256] = {0};
        html_input(html, "cap_sid", cap_sid, sizeof cap_sid);

        char cap_name[256] = {0}, cap_val[256] = {0};
        html_input_prefix(html, "cap_code_", cap_name, sizeof cap_name,
                                             cap_val,  sizeof cap_val);
        if (!*cap_name) snprintf(cap_name, sizeof cap_name, "cap_code_");

        char *eu = url_encode(g_user), *ep = url_encode(g_pass);
        char *ec = url_encode(cap_sid);
        char post[4096];
        snprintf(post, sizeof post,
                 "login_username=%s&login_password=%s&login=%%D0%%92%%D1%%85%%D0%%BE%%D0%%B4"
                 "&cap_sid=%s&%s=",
                 eu, ep, ec, cap_name);
        curl_free(eu); curl_free(ep); curl_free(ec);

        free(body.buf); body = (Buf){0};
        curl_easy_setopt(c, CURLOPT_URL,       url);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, post);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
        rc = curl_easy_perform(c);
        if (rc != CURLE_OK) { logf("login post: %s", curl_easy_strerror(rc)); goto fail; }
    }

    curl_easy_cleanup(c); free(body.buf);
    /* share the cookie jar — recreate global curl to pick up new cookies */
    curl_easy_cleanup(g_curl);
    g_curl = make_curl();
    g_logged_in = 1;
    logf("logged in to PornoLab");
    return 1;
fail:
    curl_easy_cleanup(c); free(body.buf); return 0;
}

/* fetch URL into Buf using shared session; re-login on apparent session loss */
static int session_get(const char *url, Buf *out) {
    pthread_mutex_lock(&g_curl_mtx);
    if (!g_logged_in) {
        /* try loading cookie jar first */
        struct stat st; if (stat(g_cookiefile, &st) == 0) g_logged_in = 1;
        else if (!do_login()) { pthread_mutex_unlock(&g_curl_mtx); return 0; }
    }
    curl_easy_setopt(g_curl, CURLOPT_URL,           url);
    curl_easy_setopt(g_curl, CURLOPT_HTTPGET,        1L);
    curl_easy_setopt(g_curl, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    curl_easy_setopt(g_curl, CURLOPT_WRITEDATA,      out);
    CURLcode rc = curl_easy_perform(g_curl);
    pthread_mutex_unlock(&g_curl_mtx);
    if (rc != CURLE_OK) { logf("GET %s: %s", url, curl_easy_strerror(rc)); return 0; }
    return 1;
}

/* ── bencode ─────────────────────────────────────────────────────────────── */

typedef struct BVal BVal;
struct BVal {
    int type; /* 'i' int  's' str  'l' list  'd' dict */
    union {
        long long  i;
        struct { uint8_t *p; size_t n; } s;
        struct { BVal **v; size_t n; } l;
        struct { BVal **k; BVal **v; size_t n; } d;
    };
};

static BVal *bval_new(int type) {
    BVal *b = calloc(1, sizeof *b); b->type = type; return b;
}

static BVal *bdec(const uint8_t *data, size_t len, size_t *pos);

static BVal *bdec_int(const uint8_t *d, size_t len, size_t *p) {
    size_t e = *p + 1;
    while (e < len && d[e] != 'e') e++;
    BVal *b = bval_new('i');
    char tmp[64]; size_t tl = e - *p - 1;
    if (tl >= sizeof tmp) tl = sizeof tmp - 1;
    memcpy(tmp, d + *p + 1, tl); tmp[tl] = 0;
    b->i = atoll(tmp); *p = e + 1; return b;
}

static BVal *bdec_str(const uint8_t *d, size_t len, size_t *p) {
    size_t col = *p;
    while (col < len && d[col] != ':') col++;
    char tmp[32]; size_t nl = col - *p;
    if (nl >= sizeof tmp) nl = sizeof tmp - 1;
    memcpy(tmp, d + *p, nl); tmp[nl] = 0;
    size_t n = (size_t)atol(tmp);
    BVal *b = bval_new('s');
    b->s.n = n; b->s.p = malloc(n + 1);
    memcpy(b->s.p, d + col + 1, n); b->s.p[n] = 0;
    *p = col + 1 + n; return b;
}

static BVal *bdec_list(const uint8_t *d, size_t len, size_t *p) {
    (*p)++;
    BVal *b = bval_new('l');
    size_t cap = 8;
    b->l.v = malloc(cap * sizeof(BVal *));
    while (*p < len && d[*p] != 'e') {
        if (b->l.n == cap) { cap *= 2; b->l.v = realloc(b->l.v, cap*sizeof(BVal*)); }
        b->l.v[b->l.n++] = bdec(d, len, p);
    }
    (*p)++; return b;
}

static BVal *bdec_dict(const uint8_t *d, size_t len, size_t *p) {
    (*p)++;
    BVal *b = bval_new('d');
    size_t cap = 8;
    b->d.k = malloc(cap * sizeof(BVal *));
    b->d.v = malloc(cap * sizeof(BVal *));
    while (*p < len && d[*p] != 'e') {
        if (b->d.n == cap) {
            cap *= 2;
            b->d.k = realloc(b->d.k, cap*sizeof(BVal*));
            b->d.v = realloc(b->d.v, cap*sizeof(BVal*));
        }
        b->d.k[b->d.n] = bdec(d, len, p);
        b->d.v[b->d.n] = bdec(d, len, p);
        b->d.n++;
    }
    (*p)++; return b;
}

static BVal *bdec(const uint8_t *d, size_t len, size_t *p) {
    if (*p >= len) return bval_new('i');
    uint8_t c = d[*p];
    if (c == 'i') return bdec_int(d, len, p);
    if (c == 'l') return bdec_list(d, len, p);
    if (c == 'd') return bdec_dict(d, len, p);
    if (c >= '0' && c <= '9') return bdec_str(d, len, p);
    (*p)++; return bval_new('i'); /* skip unknown */
}

static void benc(Buf *out, const BVal *b) {
    char tmp[64];
    switch (b->type) {
    case 'i':
        snprintf(tmp, sizeof tmp, "i%llde", b->i);
        buf_appendz(out, tmp); break;
    case 's':
        snprintf(tmp, sizeof tmp, "%zu:", b->s.n);
        buf_appendz(out, tmp);
        buf_append(out, b->s.p, b->s.n); break;
    case 'l':
        buf_appendz(out, "l");
        for (size_t i = 0; i < b->l.n; i++) benc(out, b->l.v[i]);
        buf_appendz(out, "e"); break;
    case 'd':
        buf_appendz(out, "d");
        /* bencode dicts must have sorted keys */
        for (size_t i = 0; i < b->d.n; i++)
            for (size_t j = i+1; j < b->d.n; j++) {
                BVal *ki = b->d.k[i], *kj = b->d.k[j];
                size_t mi = ki->s.n < kj->s.n ? ki->s.n : kj->s.n;
                int cmp = memcmp(ki->s.p, kj->s.p, mi);
                if (cmp > 0 || (cmp == 0 && ki->s.n > kj->s.n)) {
                    BVal *t; t=b->d.k[i]; b->d.k[i]=b->d.k[j]; b->d.k[j]=t;
                              t=b->d.v[i]; b->d.v[i]=b->d.v[j]; b->d.v[j]=t;
                }
            }
        for (size_t i = 0; i < b->d.n; i++) {
            benc(out, b->d.k[i]); benc(out, b->d.v[i]);
        }
        buf_appendz(out, "e"); break;
    }
}

/* locate the byte span of the top-level "info" value (to preserve hash) */
static int info_span(const uint8_t *d, size_t len,
                     size_t *start, size_t *end) {
    size_t p = 1; /* skip leading 'd' */
    while (p < len && d[p] != 'e') {
        size_t kstart = p;
        BVal *k = bdec(d, len, &p); (void)kstart;
        size_t vstart = p;
        BVal *dummy = bdec(d, len, &p);
        if (k->type == 's' && k->s.n == 4 &&
            memcmp(k->s.p, "info", 4) == 0) {
            *start = vstart; *end = p;
            free(k); free(dummy);
            return 1;
        }
        free(k); free(dummy);
    }
    return 0;
}

/* ── token store ─────────────────────────────────────────────────────────── */

#define MAX_TOKENS 16384

typedef struct { char tok[16]; char url[512]; } Token;
static Token  g_tokens[MAX_TOKENS];
static size_t g_ntok = 0;
static pthread_mutex_t g_tok_mtx = PTHREAD_MUTEX_INITIALIZER;

static const char *register_url(const char *url) {
    pthread_mutex_lock(&g_tok_mtx);
    Token *t = &g_tokens[g_ntok % MAX_TOKENS];
    /* 12 random hex chars */
    static const char hex[] = "0123456789abcdef";
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    unsigned seed = (unsigned)(ts.tv_nsec ^ (uintptr_t)url ^ g_ntok);
    for (int i = 0; i < 12; i++) {
        seed = seed * 1664525u + 1013904223u;
        t->tok[i] = hex[(seed >> 16) & 0xf];
    }
    t->tok[12] = 0;
    snprintf(t->url, sizeof t->url, "%s", url);
    g_ntok++;
    const char *tok = t->tok;
    pthread_mutex_unlock(&g_tok_mtx);
    return tok;  /* warning: points inside static array — copy before next call */
}

static const char *lookup_token(const char *tok) {
    pthread_mutex_lock(&g_tok_mtx);
    size_t n = g_ntok < MAX_TOKENS ? g_ntok : MAX_TOKENS;
    for (size_t i = 0; i < n; i++)
        if (strcmp(g_tokens[i].tok, tok) == 0) {
            pthread_mutex_unlock(&g_tok_mtx);
            return g_tokens[i].url;
        }
    pthread_mutex_unlock(&g_tok_mtx);
    return NULL;
}

/* ── announce rewriter ───────────────────────────────────────────────────── */

/* rewrite one announce URL bytes into proxy URL */
static void rewrite_url(BVal *b) {
    if (b->type != 's') return;
    if (b->s.n < 7) return;
    if (memcmp(b->s.p, "http://", 7) != 0 &&
        memcmp(b->s.p, "https://", 8) != 0) return;

    char orig[512]; size_t ol = b->s.n < 511 ? b->s.n : 511;
    memcpy(orig, b->s.p, ol); orig[ol] = 0;

    char tok[16];
    /* register_url returns pointer into static array; copy before reuse */
    memcpy(tok, register_url(orig), 13);

    char newurl[640];
    snprintf(newurl, sizeof newurl, "%s/ann?t=%s", g_self, tok);

    free(b->s.p);
    b->s.n = strlen(newurl);
    b->s.p = (uint8_t *)strdup(newurl);
}

/* find dict key by name */
static BVal *dict_get(BVal *d, const char *key) {
    for (size_t i = 0; i < d->d.n; i++)
        if (d->d.k[i]->type == 's' &&
            d->d.k[i]->s.n == strlen(key) &&
            memcmp(d->d.k[i]->s.p, key, strlen(key)) == 0)
            return d->d.v[i];
    return NULL;
}

/*
 * Rewrite announces in raw torrent bytes, preserve info dict verbatim.
 * Returns newly allocated buffer; caller frees.
 */
static uint8_t *rewrite_torrent(const uint8_t *in, size_t inlen,
                                size_t *outlen) {
    size_t p = 0;
    BVal *root = bdec(in, inlen, &p);
    if (!root || root->type != 'd') return NULL;

    BVal *ann = dict_get(root, "announce");
    if (ann) rewrite_url(ann);

    BVal *annlist = dict_get(root, "announce-list");
    if (annlist && annlist->type == 'l')
        for (size_t i = 0; i < annlist->l.n; i++) {
            BVal *tier = annlist->l.v[i];
            if (tier->type == 'l')
                for (size_t j = 0; j < tier->l.n; j++)
                    rewrite_url(tier->l.v[j]);
        }

    /* locate info span in original bytes */
    size_t istart, iend;
    if (!info_span(in, inlen, &istart, &iend)) return NULL;

    /*
     * Encode the modified root, then splice the original info bytes back in.
     * We temporarily replace info with a known placeholder string.
     */
    BVal *info_val = dict_get(root, "info");
    if (!info_val) return NULL;

    /* save and replace with placeholder */
    BVal saved = *info_val;
    uint8_t ph[] = "__INFOPH__";
    info_val->type = 's'; info_val->s.p = ph; info_val->s.n = sizeof ph - 1;

    Buf encoded = {0};
    benc(&encoded, root);
    info_val->type = saved.type; info_val->s = saved.s; /* restore (union) */

    /* build the needle: bencode("info") + bencode("__INFOPH__") */
    Buf needle = {0};
    BVal kv = {'s', .s = {(uint8_t*)"info", 4}};
    BVal pv = {'s', .s = {ph, sizeof ph - 1}};
    benc(&needle, &kv);
    benc(&needle, &pv);

    uint8_t *found = (uint8_t *)memmem(encoded.buf, encoded.len,
                                       needle.buf, needle.len);
    if (!found) { free(encoded.buf); free(needle.buf); return NULL; }

    /* replace placeholder region with original info bytes */
    size_t ph_offset = (size_t)(found - encoded.buf) + 6; /* past bencode("info") */
    size_t ph_len    = needle.len - 6;
    size_t info_orig_len = iend - istart;

    Buf out = {0};
    buf_append(&out, encoded.buf, ph_offset);
    buf_append(&out, in + istart, info_orig_len);
    buf_append(&out, encoded.buf + ph_offset + ph_len,
               encoded.len - ph_offset - ph_len);

    free(encoded.buf); free(needle.buf);
    *outlen = out.len;
    return out.buf;
}

/* ── HTTP server ─────────────────────────────────────────────────────────── */

/* read one line from fd (strip \r\n), return 0 on EOF */
static int readline(int fd, char *buf, size_t sz) {
    size_t i = 0; char c;
    while (i + 1 < sz) {
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) break;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = 0; return i > 0;
}

/* write full string to fd */
static void writen(int fd, const void *buf, size_t n) {
    const char *p = buf; ssize_t w;
    while (n > 0 && (w = write(fd, p, n)) > 0) { p += w; n -= w; }
}
static void writes(int fd, const char *s) { writen(fd, s, strlen(s)); }

/* send HTTP response */
static void respond(int fd, int code, const char *ctype,
                    const uint8_t *body, size_t blen,
                    const char *extra_hdr) {
    const char *reason = code == 200 ? "OK"
                       : code == 204 ? "No Content"
                       : code == 400 ? "Bad Request"
                       : code == 403 ? "Forbidden"
                       : code == 404 ? "Not Found"
                       : code == 429 ? "Too Many Requests"
                       : code == 503 ? "Service Unavailable"
                       :               "Error";
    char hdr[512];
    snprintf(hdr, sizeof hdr,
             "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
             "Connection: close\r\n%s\r\n",
             code, reason, ctype, blen,
             extra_hdr ? extra_hdr : "");
    writes(fd, hdr);
    if (body && blen) writen(fd, body, blen);
}

/* parse ?key=value from raw query string (url-decoded into val, max valsz) */
static int qs_get(const char *qs, const char *key,
                  char *val, size_t valsz) {
    size_t kl = strlen(key); *val = 0;
    const char *p = qs;
    while (p && *p) {
        if (strncmp(p, key, kl) == 0 && p[kl] == '=') {
            p += kl + 1;
            int out = 0;
            char tmp[3] = {0};
            while (*p && *p != '&' && (size_t)out + 1 < valsz) {
                if (*p == '%' && p[1] && p[2]) {
                    tmp[0]=p[1]; tmp[1]=p[2];
                    val[out++] = (char)strtol(tmp, NULL, 16); p += 3;
                } else if (*p == '+') { val[out++] = ' '; p++; }
                else val[out++] = *p++;
            }
            val[out] = 0; return 1;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return 0;
}

/* check API key if configured; return 1 if OK */
static int check_apikey(int fd, const char *qs, const char *apikey_hdr) {
    if (!g_apikey || !*g_apikey) return 1;
    char k[256];
    if (qs_get(qs, "apikey", k, sizeof k) && strcmp(k, g_apikey) == 0) return 1;
    if (apikey_hdr && strcmp(apikey_hdr, g_apikey) == 0) return 1;
    respond(fd, 403, "text/plain", (uint8_t*)"forbidden", 9, NULL);
    return 0;
}

/* ── handlers ────────────────────────────────────────────────────────────── */

static void handle_dl(int fd, const char *path, const char *qs,
                      const char *apikey_hdr) {
    if (!check_apikey(fd, qs, apikey_hdr)) return;

    const char *id_str = path + 4; /* skip "/dl/" */
    for (const char *c = id_str; *c; c++)
        if (*c < '0' || *c > '9') {
            respond(fd, 400, "text/plain", (uint8_t*)"bad topic id", 12, NULL);
            return;
        }

    char url[512];
    snprintf(url, sizeof url, "%s/forum/dl.php?t=%s", g_base, id_str);

    Buf body = {0};
    if (!session_get(url, &body)) {
        respond(fd, 502, "text/plain", (uint8_t*)"upstream error", 14, NULL);
        return;
    }

    /* check we got a torrent and not an HTML page */
    if (body.len < 10 || body.buf[0] != 'd' ||
        memmem(body.buf, body.len < 4096 ? body.len : 4096,
               "4:info", 6) == NULL) {
        int code = memmem(body.buf, body.len < 512 ? body.len : 512,
                          "limit", 5) ? 429 : 503;
        respond(fd, code, "text/plain",
                (uint8_t*)"PornoLab returned a page instead of a .torrent",
                46, NULL);
        free(body.buf); return;
    }

    size_t outlen = 0;
    uint8_t *out = rewrite_torrent(body.buf, body.len, &outlen);
    free(body.buf);
    if (!out) {
        respond(fd, 502, "text/plain", (uint8_t*)"torrent parse error", 19, NULL);
        return;
    }

    char disp[128];
    snprintf(disp, sizeof disp,
             "Content-Disposition: attachment; filename=\"%s.torrent\"\r\n",
             id_str);
    respond(fd, 200, "application/x-bittorrent", out, outlen, disp);
    free(out);
}

static void handle_ann(int fd, const char *qs) {
    char tok[64];
    if (!qs_get(qs, "t", tok, sizeof tok)) {
        respond(fd, 200, "text/plain",
                (uint8_t*)"d14:failure reason9:bad tokene", 30, NULL);
        return;
    }
    const char *real = lookup_token(tok);
    if (!real) {
        respond(fd, 200, "text/plain",
                (uint8_t*)"d14:failure reason9:bad tokene", 30, NULL);
        return;
    }

    /* rebuild query string: strip t=, clamp downloaded=0 */
    char newqs[2048] = {0}; size_t pos = 0;
    const char *p = qs;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        size_t seglen = amp ? (size_t)(amp - p) : strlen(p);
        char seg[256]; if (seglen >= sizeof seg) seglen = sizeof seg - 1;
        memcpy(seg, p, seglen); seg[seglen] = 0;

        int skip = (strncmp(seg, "t=", 2) == 0);
        int is_dl = (strncmp(seg, "downloaded=", 11) == 0);

        if (!skip) {
            if (pos + 1 < sizeof newqs) newqs[pos++] = pos == 0 ? '\0' : '&';
            const char *val = is_dl ? "downloaded=0" : seg;
            size_t vl = strlen(val);
            if (pos + vl < sizeof newqs) { memcpy(newqs + pos, val, vl); pos += vl; }
        }
        p = amp ? amp + 1 : NULL;
    }
    /* if downloaded was not in original query, append it */
    if (!strstr(qs, "downloaded=")) {
        snprintf(newqs + pos, sizeof newqs - pos, "&downloaded=0");
    } else if (pos > 0 && newqs[0] == '\0') {
        /* fix leading delimiter we wrote when pos was 0 */
        memmove(newqs, newqs + 1, pos);
    }

    char fwd_url[1024];
    snprintf(fwd_url, sizeof fwd_url, "%s%s%s",
             real, strchr(real, '?') ? "&" : "?", newqs);

    CURL *c = curl_easy_init();
    curl_easy_setopt(c, CURLOPT_URL,           fwd_url);
    curl_easy_setopt(c, CURLOPT_USERAGENT,     "Mozilla/5.0");
    curl_easy_setopt(c, CURLOPT_TIMEOUT,       20L);
    Buf resp = {0};
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,     &resp);
    CURLcode rc = curl_easy_perform(c);
    curl_easy_cleanup(c);

    if (rc != CURLE_OK || !resp.len) {
        respond(fd, 200, "text/plain",
                (uint8_t*)"d14:failure reason11:proxy errore", 32, NULL);
    } else {
        respond(fd, 200, "text/plain", resp.buf, resp.len, NULL);
    }
    free(resp.buf);
}

/* ── connection thread ───────────────────────────────────────────────────── */

typedef struct { int fd; } ConnArg;

static void *handle_conn(void *arg) {
    int fd = ((ConnArg *)arg)->fd;
    free(arg);

    char line[4096];
    if (!readline(fd, line, sizeof line)) { close(fd); return NULL; }

    /* expect: GET /path?query HTTP/1.x */
    if (strncmp(line, "GET ", 4) != 0) { close(fd); return NULL; }
    char *sp = strchr(line + 4, ' ');
    if (sp) *sp = 0;
    char *raw_path = line + 4;
    char *qs = strchr(raw_path, '?');
    if (qs) { *qs = 0; qs++; } else qs = (char*)"";

    /* read headers to find X-Api-Key */
    char apikey_hdr[256] = {0};
    char hline[1024];
    while (readline(fd, hline, sizeof hline) && hline[0]) {
        if (strncasecmp(hline, "X-Api-Key:", 10) == 0) {
            char *v = hline + 10; while (*v == ' ') v++;
            snprintf(apikey_hdr, sizeof apikey_hdr, "%s", v);
        }
    }

    if (strcmp(raw_path, "/healthz") == 0) {
        respond(fd, 200, "text/plain", (uint8_t*)"ok", 2, NULL);
    } else if (strncmp(raw_path, "/dl/", 4) == 0) {
        handle_dl(fd, raw_path, qs, apikey_hdr[0] ? apikey_hdr : NULL);
    } else if (strcmp(raw_path, "/ann") == 0) {
        handle_ann(fd, qs);
    } else {
        respond(fd, 404, "text/plain", (uint8_t*)"not found", 9, NULL);
    }

    close(fd);
    return NULL;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void) {
    g_base   = getenv("PORNOLAB_URL")      ?: "https://pornolab.net";
    g_user   = getenv("PORNOLAB_USERNAME") ?: "";
    g_pass   = getenv("PORNOLAB_PASSWORD") ?: "";
    g_self   = getenv("PROXY_SELF_URL")    ?: "http://127.0.0.1:8008";
    g_data   = getenv("PROXY_DATA_DIR")    ?: "/config/proxy";
    g_apikey = getenv("PROXY_API_KEY")     ?: "";
    g_port   = atoi(getenv("PROXY_PORT") ?: "8008");
    if (g_port <= 0 || g_port > 65535) g_port = 8008;

    snprintf(g_cookiefile, sizeof g_cookiefile, "%s/cookies.txt", g_data);
    mkdir(g_data, 0700);

    curl_global_init(CURL_GLOBAL_ALL);
    g_curl = make_curl();

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(g_port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, 32);
    logf("listening on port %d", g_port);

    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        ConnArg *a = malloc(sizeof *a); a->fd = fd;
        pthread_t t;
        pthread_attr_t attr; pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&t, &attr, handle_conn, a);
        pthread_attr_destroy(&attr);
    }
}
