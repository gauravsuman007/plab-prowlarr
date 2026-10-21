/*
 * torrent-proxy.c — announce-rewriting proxy for PornoLab
 *
 * Build (Alpine musl, static):
 *   apk add gcc musl-dev libcurl-dev
 *   gcc -O2 -o proxy proxy.c -lcurl -lpthread
 *
 * GET /dl/<topic_id>   fetch .torrent, rewrite announces, return bytes
 * GET /ann?t=<tok>&…   forward announce with downloaded=0
 * GET /quota           today's .torrent allowance and the profile's downloaded total (JSON); loopback only
 * GET /quota-row       the same as one result row, for the indexer's second search path; loopback only
 * GET /quota/dump      save the profile page's text to <data dir>/profile_dump.txt
 * GET /healthz         liveness check
 *
 * Environment (all optional — credentials can be passed per-request instead):
 *   PORNOLAB_URL       default https://pornolab.net
 *   PORNOLAB_USERNAME  fallback if not supplied per-request
 *   PORNOLAB_PASSWORD  fallback if not supplied per-request
 *   PROXY_SELF_URL     base URL qBittorrent uses to reach this proxy
 *                      default http://127.0.0.1:8008
 *   PROXY_PORT         default 8008
 *   PROXY_DATA_DIR     cookie jar directory, default /config/proxy
 *   PROXY_API_KEY      optional; if set, /dl and /ann callers other than 127.0.0.1 must send ?apikey= or X-Api-Key
 *   QUOTA_ENFORCE      default 1: /dl answers 429 once today's .torrent allowance is used up; 0 disables
 *   ANNOUNCE_PROXY_URL external announce-proxy container (its announce port). When set,
 *                      announce URLs are registered there and the returned torrent carries
 *                      ITS url; this process's own /ann is then unused. If the proxy can't
 *                      be reached the download fails: a torrent is never returned with
 *                      the real tracker URL in it.
 *   ANNOUNCE_PROXY_KEY this client's key from the announce-proxy's Clients tab
 *   Session: by default the sidecar borrows the PornoLab session Prowlarr itself holds (its saved
 *   cookies for the indexer, read from <PROWLARR_CONFIG_DIR>/prowlarr.db, default /config), so it
 *   never has to log in or solve a login captcha; PROWLARR_SESSION=0 turns that off. It also sends
 *   what Prowlarr sends: its User-Agent ("Prowlarr/<version> (<os> <version>)", read from Prowlarr's
 *   own status API, override with PORNOLAB_USER_AGENT), Accept-Encoding, Connection: close, a
 *   traceparent header, and no Accept header. Order of preference for the session:
 *   PORNOLAB_COOKIE, then Prowlarr's cookies, then the sidecar's own login.
 *   PORNOLAB_COOKIE    optional: a logged-in Cookie header (e.g. "bb_data=...") copied from a
 *                      browser. When set the proxy never logs in itself, which sidesteps the
 *                      login captcha PornoLab sometimes demands.
 *
 * Per-request credentials (preferred — stored in Prowlarr's own config DB):
 *   GET /dl/<id>?u=<username>&p=<password>
 *   These override env vars and are never forwarded to trackers.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sqlite3.h>
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
static const char *g_annproxy;    /* ANNOUNCE_PROXY_URL */
static const char *g_annkey;      /* ANNOUNCE_PROXY_KEY */
static __thread char t_label[256];       /* account name shown on the announce-proxy dashboard */
static __thread int  t_rewrite_failed;   /* set when an announce URL could not be proxied */
static const char *g_cookie;      /* PORNOLAB_COOKIE */
static const char *g_prowlarr_dir;       /* PROWLARR_CONFIG_DIR (default /config) */
static int         g_use_prowlarr_session = 1;   /* PROWLARR_SESSION=0 disables */
static const char *g_ua_override;        /* PORNOLAB_USER_AGENT */
static char        g_ua[200];            /* Prowlarr's own User-Agent, once known */
static time_t      g_ua_at;
static char        g_refused_cookie[1500];   /* the Prowlarr cookie header the site last rejected: skip exactly that one */
static char        g_last_borrowed[1500];    /* the Prowlarr cookie header used for the latest request */
static pthread_mutex_t g_ua_mtx = PTHREAD_MUTEX_INITIALIZER;
static int         g_quota_enforce = 1;   /* QUOTA_ENFORCE=0 turns the refusal off (the /quota endpoint stays) */
static __thread int t_peer_loopback;      /* this connection came from 127.0.0.1 */
static __thread char t_login_err[160];   /* why the last login attempt failed, for the HTTP reply */
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

/* What a PornoLab response is. The pages are Windows-1251, so only ASCII markers are matched. */
enum { PG_TORRENT, PG_CAPTCHA, PG_LOGIN_FORM, PG_OTHER };
static int classify_page(const uint8_t *b, size_t n) {
    if (!b || n == 0) return PG_OTHER;
    if (n >= 10 && b[0] == 'd' && memmem(b, n < 4096 ? n : 4096, "4:info", 6)) return PG_TORRENT;
    size_t m = n < 262144 ? n : 262144;
    if (memmem(b, m, "cap_code_", 9) || memmem(b, m, "/captcha/", 9)) return PG_CAPTCHA;
    if (memmem(b, m, "login_username", 14)) return PG_LOGIN_FORM;
    return PG_OTHER;
}

/* ── session (curl with cookie jar) ─────────────────────────────────────── */

static CURL          *g_curl;
static pthread_mutex_t g_curl_mtx = PTHREAD_MUTEX_INITIALIZER;
static int             g_logged_in = 0;

static CURL *make_curl(void) {
    CURL *c = curl_easy_init();
    curl_easy_setopt(c, CURLOPT_USERAGENT,      g_ua[0] ? g_ua : "Mozilla/5.0");
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION,  1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,         30L);
    curl_easy_setopt(c, CURLOPT_FORBID_REUSE,    1L);          /* Prowlarr sends Connection: close */
    curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);
    curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, (vi && (vi->features & CURL_VERSION_BROTLI)) ? "gzip, br" : "gzip");
    curl_easy_setopt(c, CURLOPT_COOKIEJAR,       g_cookiefile);
    curl_easy_setopt(c, CURLOPT_COOKIEFILE,      g_cookiefile);
    if (g_cookie && *g_cookie) curl_easy_setopt(c, CURLOPT_COOKIE, g_cookie);
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

static struct curl_slist *prowlarr_like_headers(void);
static void ensure_ua(void);

/* login with explicit user/pass (overrides env vars) */
static int do_login_as(const char *user, const char *pass) {
    t_login_err[0] = 0;
    if (!user || !*user || !pass || !*pass) {
        snprintf(t_login_err, sizeof t_login_err, "no PornoLab credentials available");
        logf("ERROR: no credentials available"); return 0;
    }
    CURL *c = make_curl();
    ensure_ua();
    if (g_ua[0]) curl_easy_setopt(c, CURLOPT_USERAGENT, g_ua);
    struct curl_slist *lh = prowlarr_like_headers();       /* the same request headers as Prowlarr */
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, lh);
    Buf body = {0};
    char url[1024]; snprintf(url, sizeof url, "%s/forum/login.php", g_base);

    /* fetch login page */
    curl_easy_setopt(c, CURLOPT_URL,            url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,      &body);
    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) {
        snprintf(t_login_err, sizeof t_login_err, "could not reach PornoLab");
        logf("login page fetch: %s", curl_easy_strerror(rc)); goto fail;
    }

    {
        char html[65536]; size_t hl = body.len < sizeof html - 1 ? body.len : sizeof html - 1;
        memcpy(html, body.buf, hl); html[hl] = 0;

        char cap_sid[256] = {0};
        html_input(html, "cap_sid", cap_sid, sizeof cap_sid);

        char cap_name[256] = {0}, cap_val[256] = {0};
        html_input_prefix(html, "cap_code_", cap_name, sizeof cap_name,
                                             cap_val,  sizeof cap_val);
        if (!*cap_name) snprintf(cap_name, sizeof cap_name, "cap_code_");

        char *eu = url_encode(user), *ep = url_encode(pass);
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
        if (rc != CURLE_OK) {
            snprintf(t_login_err, sizeof t_login_err, "could not reach PornoLab");
            logf("login post: %s", curl_easy_strerror(rc)); goto fail;
        }
    }

    /* The page after a successful login carries the logout link. Anything else means the
     * login was not accepted, however 200 OK the response was. */
    if (!(body.buf && body.len && memmem(body.buf, body.len, "logout", 6))) {
        int pg = classify_page(body.buf, body.len);
        snprintf(t_login_err, sizeof t_login_err, "%s",
                 pg == PG_CAPTCHA ? "PornoLab demands a captcha at login; log in once from a browser on this network, or set PORNOLAB_COOKIE"
               : pg == PG_LOGIN_FORM ? "PornoLab rejected the username or password"
               : "PornoLab login returned an unexpected page");
        logf("login failed: %s", t_login_err);
        unlink(g_cookiefile);                 /* never keep a cookie jar from a failed login */
        goto fail;
    }

    /* Both handles write the same cookie jar when they are destroyed, and the last one wins.
     * The old shared handle goes first (it flushes its stale jar), then the login handle, so the
     * fresh login cookies are what ends up on disk; the new shared handle then reads them. */
    curl_easy_cleanup(g_curl);
    curl_easy_cleanup(c); curl_slist_free_all(lh); free(body.buf);
    g_curl = make_curl();
    g_logged_in = 1;
    logf("logged in to PornoLab");
    return 1;
fail:
    curl_easy_cleanup(c); curl_slist_free_all(lh); free(body.buf); return 0;
}

/* Drop whatever session we think we have (jar file and the live handle's cookies) so the next
 * request logs in afresh. */
static void forget_session(void) {
    snprintf(g_refused_cookie, sizeof g_refused_cookie, "%s", g_last_borrowed);   /* if that was Prowlarr's session, don't reuse that exact cookie */
    pthread_mutex_lock(&g_curl_mtx);
    unlink(g_cookiefile);
    curl_easy_setopt(g_curl, CURLOPT_COOKIELIST, "ALL");
    g_logged_in = 0;
    pthread_mutex_unlock(&g_curl_mtx);
}

static int do_login(void) {
    return do_login_as(g_user, g_pass);
}

/* ── borrowing Prowlarr's identity ───────────────────────────────────────── */

/* Parse the next JSON string at p (which points at its opening quote) into out, unescaping. */
static const char *json_string(const char *p, char *out, size_t sz) {
    size_t k = 0; p++;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) {
            char e = *p++;
            if (e == 'u' && p[0] && p[1] && p[2] && p[3]) { char h[5] = {p[0], p[1], p[2], p[3], 0}; c = (char)strtol(h, NULL, 16); p += 4; }
            else c = e == 'n' ? '\n' : e == 't' ? '\t' : e;     /* \" \\ \/ come through as themselves */
        }
        if (k + 1 < sz) out[k++] = c;
    }
    out[k] = 0;
    return *p == '"' ? p + 1 : p;
}

/* Value of a top-level-looking "key": "value" pair anywhere in a JSON text (spaces around ':' allowed). */
static int json_find_string(const char *j, const char *key, char *out, size_t sz) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", key);
    for (const char *q = j; (q = strstr(q, pat)); q += strlen(pat)) {
        const char *v = q + strlen(pat);
        while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
        if (*v != ':') continue;
        v++; while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
        if (*v != '"') continue;
        json_string(v, out, sz); return 1;
    }
    out[0] = 0; return 0;
}

/* The PornoLab session cookies Prowlarr saved for its indexer (IndexerStatus.Cookies), as a
 * Cookie header. Returns 0 if there are none, they have expired, or the site refused them lately. */
static int prowlarr_cookie_header(char *out, size_t sz) {
    out[0] = 0;
    time_t now = time(NULL);
    if (!g_use_prowlarr_session) return 0;
    char path[600]; snprintf(path, sizeof path, "%s/prowlarr.db", g_prowlarr_dir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) { if (db) sqlite3_close(db); return 0; }
    sqlite3_busy_timeout(db, 1500);
    sqlite3_stmt *st = NULL; int ok = 0;
    if (sqlite3_prepare_v2(db,
            "select s.Cookies, s.CookiesExpirationDate from IndexerStatus s join Indexers i on i.Id = s.ProviderId "
            "where instr(i.Settings, 'pornolab') > 0 and s.Cookies is not null and length(s.Cookies) > 2 "
            "order by s.CookiesExpirationDate desc limit 1", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        const char *json = (const char *)sqlite3_column_text(st, 0);
        const char *exp  = (const char *)sqlite3_column_text(st, 1);
        char nowstr[24]; struct tm tmv; gmtime_r(&now, &tmv); strftime(nowstr, sizeof nowstr, "%Y-%m-%d %H:%M:%S", &tmv);
        int expired = exp && strlen(exp) >= 19 && strncmp(exp, nowstr, 19) < 0;
        if (json && !expired) {
            size_t n = 0;
            for (const char *p = json; (p = strchr(p, '"')); ) {
                char key[128], val[1024];
                p = json_string(p, key, sizeof key);
                while (*p == ' ' || *p == ':') p++;
                if (*p != '"') continue;                       /* not a string value */
                p = json_string(p, val, sizeof val);
                n += (size_t)snprintf(out + n, n < sz ? sz - n : 0, "%s%s=%s", n ? "; " : "", key, val);
                if (n + 1 >= sz) { n = sz - 1; break; }
            }
            ok = n > 0;
        }
    }
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
    if (ok && g_refused_cookie[0] && strcmp(out, g_refused_cookie) == 0) { out[0] = 0; ok = 0; }   /* the site already said no to this one */
    static int announced = -1;
    if (announced != ok) { announced = ok; logf(ok ? "using the PornoLab session saved by Prowlarr" : "no usable Prowlarr session for PornoLab; falling back"); }
    return ok;
}

/* Prowlarr's User-Agent is "Prowlarr/<version> (<os> <os version>)"; its own status API has the three
 * parts. Refreshed hourly. PORNOLAB_USER_AGENT overrides. */
static void ensure_ua(void) {
    pthread_mutex_lock(&g_ua_mtx);
    time_t now = time(NULL);
    if (g_ua_override && *g_ua_override) { snprintf(g_ua, sizeof g_ua, "%s", g_ua_override); pthread_mutex_unlock(&g_ua_mtx); return; }
    if (g_ua[0] && now - g_ua_at < 3600) { pthread_mutex_unlock(&g_ua_mtx); return; }
    g_ua_at = now;                                    /* don't retry on every request if Prowlarr is unreachable */
    char cfg[600]; snprintf(cfg, sizeof cfg, "%s/config.xml", g_prowlarr_dir);
    FILE *f = fopen(cfg, "r");
    if (f) {
        char xml[8192]; size_t n = fread(xml, 1, sizeof xml - 1, f); xml[n] = 0; fclose(f);
        char key[80] = "", port[8] = "9696", base[80] = "";
        const char *a;
        if ((a = strstr(xml, "<ApiKey>"))) { a += 8; size_t k = strcspn(a, "<"); if (k < sizeof key) { memcpy(key, a, k); key[k] = 0; } }
        if ((a = strstr(xml, "<Port>")))    { a += 6; size_t k = strcspn(a, "<"); if (k < sizeof port) { memcpy(port, a, k); port[k] = 0; } }
        if ((a = strstr(xml, "<UrlBase>"))) { a += 9; size_t k = strcspn(a, "<"); if (k < sizeof base) { memcpy(base, a, k); base[k] = 0; } }
        if (key[0]) {
            char url[300], hdr[120]; Buf body = {0};
            snprintf(url, sizeof url, "http://127.0.0.1:%s%s%s/api/v1/system/status", port, base[0] && base[0] != '/' ? "/" : "", base);
            snprintf(hdr, sizeof hdr, "X-Api-Key: %s", key);
            CURL *c = curl_easy_init(); struct curl_slist *h = curl_slist_append(NULL, hdr);
            curl_easy_setopt(c, CURLOPT_URL, url); curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
            curl_easy_setopt(c, CURLOPT_TIMEOUT, 4L); curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
            curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
            if (curl_easy_perform(c) == CURLE_OK && body.len) {
                buf_append(&body, "\0", 1);
                char ver[40] = "", os[40] = "", osv[40] = ""; const char *j = (const char *)body.buf;
                const char *q;
                json_find_string(j, "version", ver, sizeof ver);
                json_find_string(j, "osName", os, sizeof os);
                json_find_string(j, "osVersion", osv, sizeof osv);
                if (ver[0]) {
                    if (os[0] && osv[0]) snprintf(g_ua, sizeof g_ua, "Prowlarr/%s (%s %s)", ver, os, osv);
                    else snprintf(g_ua, sizeof g_ua, "Prowlarr/%s", ver);
                    logf("using Prowlarr's User-Agent: %s", g_ua);
                }
            }
            curl_slist_free_all(h); curl_easy_cleanup(c); free(body.buf);
        }
    }
    pthread_mutex_unlock(&g_ua_mtx);
}

static void random_hex(char *out, size_t nbytes) {            /* out gets 2*nbytes hex chars + NUL */
    uint8_t b[16]; FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(b, 1, nbytes, f) != nbytes) for (size_t i = 0; i < nbytes; i++) b[i] = (uint8_t)rand();
    if (f) fclose(f);
    for (size_t i = 0; i < nbytes; i++) snprintf(out + 2 * i, 3, "%02x", b[i]);
}

/* The request headers Prowlarr sends (no Accept, Connection: close, a fresh W3C traceparent). */
static struct curl_slist *prowlarr_like_headers(void) {
    char tid[33], sid[17], tp[80];
    random_hex(tid, 16); random_hex(sid, 8);
    snprintf(tp, sizeof tp, "traceparent: 00-%s-%s-00", tid, sid);
    struct curl_slist *hl = curl_slist_append(NULL, "Accept:");
    hl = curl_slist_append(hl, "Connection: close");
    return curl_slist_append(hl, tp);
}

/* fetch URL into Buf using shared session.
 * user/pass: per-request credentials (from ?u=&p=); NULL falls back to env vars. */
static int session_get(const char *url, Buf *out,
                       const char *user, const char *pass) {
    ensure_ua();
    /* Whose session? PORNOLAB_COOKIE, else the one Prowlarr saved, else our own login. */
    char borrowed[1500]; int use_prowlarr = 0;
    if (!(g_cookie && *g_cookie)) use_prowlarr = prowlarr_cookie_header(borrowed, sizeof borrowed);
    pthread_mutex_lock(&g_curl_mtx);
    if (!g_logged_in) {
        struct stat st;
        if (g_cookie && *g_cookie) {
            g_logged_in = 1;                  /* PORNOLAB_COOKIE is the session; we never log in ourselves */
        } else if (use_prowlarr) {
            g_logged_in = 1;
        } else if (stat(g_cookiefile, &st) == 0) {
            g_logged_in = 1;
        } else {
            const char *u = (user && *user) ? user : g_user;
            const char *p = (pass && *pass) ? pass : g_pass;
            if (!do_login_as(u, p)) { pthread_mutex_unlock(&g_curl_mtx); return 0; }
        }
    }
    snprintf(g_last_borrowed, sizeof g_last_borrowed, "%s", use_prowlarr ? borrowed : "");
    if (use_prowlarr) {                       /* exactly Prowlarr's cookies, nothing left over from other sessions */
        curl_easy_setopt(g_curl, CURLOPT_COOKIELIST, "ALL");
        curl_easy_setopt(g_curl, CURLOPT_COOKIE, borrowed);
    } else if (!(g_cookie && *g_cookie)) {
        curl_easy_setopt(g_curl, CURLOPT_COOKIE, NULL);
    }
    if (g_ua[0]) curl_easy_setopt(g_curl, CURLOPT_USERAGENT, g_ua);
    struct curl_slist *hl = prowlarr_like_headers();
    curl_easy_setopt(g_curl, CURLOPT_HTTPHEADER,    hl);
    curl_easy_setopt(g_curl, CURLOPT_URL,           url);
    curl_easy_setopt(g_curl, CURLOPT_HTTPGET,        1L);
    curl_easy_setopt(g_curl, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    curl_easy_setopt(g_curl, CURLOPT_WRITEDATA,      out);
    CURLcode rc = curl_easy_perform(g_curl);
    curl_easy_setopt(g_curl, CURLOPT_HTTPHEADER, NULL);
    curl_slist_free_all(hl);
    pthread_mutex_unlock(&g_curl_mtx);
    if (rc != CURLE_OK) { logf("GET %s: %s", url, curl_easy_strerror(rc)); return 0; }
    return 1;
}

/* ── profile and the daily .torrent quota ────────────────────────────────── */

/* PornoLab's pages are windows-1251. Turn one into plain UTF-8 text (tags, scripts and styles
 * dropped, entities decoded, whitespace collapsed) so the labels below can be matched as
 * ordinary strings, the same way the seeder's Python parser reads the visible text. */
static void put_utf8(Buf *o, unsigned cp) {
    uint8_t b[3];
    if (cp == 0) return;                      /* a NUL in the text would end every strstr early */
    if (cp < 0x80)       { b[0] = (uint8_t)cp; buf_append(o, b, 1); }
    else if (cp < 0x800) { b[0] = 0xC0 | (cp >> 6); b[1] = 0x80 | (cp & 63); buf_append(o, b, 2); }
    else                 { b[0] = 0xE0 | (cp >> 12); b[1] = 0x80 | ((cp >> 6) & 63); b[2] = 0x80 | (cp & 63); buf_append(o, b, 3); }
}

static unsigned cp1251_cp(uint8_t c) {
    if (c < 0x80) return c;
    if (c >= 0xC0) return 0x410 + (c - 0xC0);
    switch (c) {
    case 0xA8: return 0x401;  case 0xB8: return 0x451;  case 0xA0: return ' ';
    case 0xAB: return 0xAB;   case 0xBB: return 0xBB;   case 0x96: return 0x2013;
    case 0x97: return 0x2014; case 0x85: return 0x2026; case 0xB9: return 0x2116;
    }
    return '?';
}

static const uint8_t *find_ci(const uint8_t *h, size_t n, const char *needle) {
    size_t m = strlen(needle);
    for (size_t i = 0; i + m <= n; i++)
        if (strncasecmp((const char *)h + i, needle, m) == 0) return h + i;
    return NULL;
}

static void html_to_text(const uint8_t *in, size_t n, Buf *out) {
    int last_space = 1;
    for (size_t i = 0; i < n;) {
        uint8_t c = in[i];
        if (c == '<') {
            const char *skip_to = NULL;
            if (i + 7 <= n && strncasecmp((const char *)in + i + 1, "script", 6) == 0) skip_to = "</script";
            else if (i + 6 <= n && strncasecmp((const char *)in + i + 1, "style", 5) == 0) skip_to = "</style";
            const uint8_t *e = memchr(in + i, '>', n - i);
            size_t next = e ? (size_t)(e - in) + 1 : n;
            if (skip_to) {
                const uint8_t *close = find_ci(in + next, n - next, skip_to);
                const uint8_t *ce = close ? memchr(close, '>', n - (size_t)(close - in)) : NULL;
                next = ce ? (size_t)(ce - in) + 1 : n;
            }
            i = next;
            if (!last_space) { buf_append(out, " ", 1); last_space = 1; }
            continue;
        }
        if (c == '&') {
            size_t j = i + 1;
            while (j < n && j - i < 9 && in[j] != ';' && in[j] != ' ' && in[j] != '<') j++;
            if (j < n && in[j] == ';') {
                char ent[12]; size_t el = j - i - 1; if (el >= sizeof ent) el = sizeof ent - 1;
                memcpy(ent, in + i + 1, el); ent[el] = 0;
                unsigned cp = 0; int known = 1;
                if (!strcmp(ent, "nbsp")) cp = ' ';
                else if (!strcmp(ent, "amp")) cp = '&';
                else if (!strcmp(ent, "lt")) cp = '<';
                else if (!strcmp(ent, "gt")) cp = '>';
                else if (!strcmp(ent, "quot")) cp = '"';
                else if (ent[0] == '#' && (ent[1] == 'x' || ent[1] == 'X')) cp = (unsigned)strtoul(ent + 2, NULL, 16);   /* &#x2022; */
                else if (ent[0] == '#' && ent[1]) cp = (unsigned)strtoul(ent + 1, NULL, 10);
                else known = 0;
                if (known) {
                    if (cp < 0x21 || cp == 160) { if (!last_space) { buf_append(out, " ", 1); last_space = 1; } }   /* never a NUL or control char */
                    else { put_utf8(out, cp); last_space = 0; }
                    i = j + 1; continue;
                }
            }
        }
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0xA0 || c < 0x20) {   /* control bytes (a stray NUL!) count as a space */
            if (!last_space) { buf_append(out, " ", 1); last_space = 1; }
        } else { put_utf8(out, cp1251_cp(c)); last_space = 0; }
        i++;
    }
    buf_append(out, "\0", 1);
}

typedef unsigned long long u64;
typedef struct { u64 last, today, yesterday, total; } Stat;
typedef struct {
    char username[64];
    double rating; int has_rating;
    int newbie;
    u64 uploaded, uploaded_own, uploaded_bonus, downloaded;
    Stat down, up, own, bonus;
} Prof;

static const char *sk(const char *p) { while (*p == ' ') p++; return p; }

static int parse_dbl(const char **pp, double *v) {
    const char *p = sk(*pp);
    if (!(*p >= '0' && *p <= '9')) return 0;
    char tmp[40]; size_t k = 0;
    while (k < sizeof tmp - 1 && ((*p >= '0' && *p <= '9') || *p == '.' || *p == ',')) { tmp[k++] = *p == ',' ? '.' : *p; p++; }
    tmp[k] = 0; *v = strtod(tmp, NULL); *pp = p; return 1;
}

static int parse_u64(const char **pp, u64 *v) {
    const char *p = sk(*pp);
    if (!(*p >= '0' && *p <= '9')) return 0;
    *v = 0;
    while (*p >= '0' && *p <= '9') { *v = *v * 10 + (u64)(*p - '0'); p++; }
    *pp = p; return 1;
}

/* '989.7 MB' -> bytes. PornoLab's units are binary. */
static int parse_size(const char **pp, u64 *out) {
    const char *p = *pp; double v;
    if (!parse_dbl(&p, &v)) return 0;
    p = sk(p);
    static const struct { const char *u; double m; } units[] = {
        {"TB", 1099511627776.0}, {"GB", 1073741824.0}, {"MB", 1048576.0}, {"KB", 1024.0}, {"B", 1.0}};
    for (size_t i = 0; i < sizeof units / sizeof *units; i++) {
        size_t ul = strlen(units[i].u);
        if (strncasecmp(p, units[i].u, ul) == 0 && !((p[ul] >= 'A' && p[ul] <= 'Z') || (p[ul] >= 'a' && p[ul] <= 'z') || (p[ul] >= '0' && p[ul] <= '9'))) {
            *out = (u64)(v * units[i].m); *pp = p + ul; return 1;
        }
    }
    return 0;
}

static int lit(const char **pp, const char *s) {       /* skip spaces, then require the literal */
    const char *p = sk(*pp); size_t l = strlen(s);
    if (strncmp(p, s, l) != 0) return 0;
    *pp = p + l; return 1;
}

static int is_unit_at(const char *p) {                 /* TB | GB | MB | KB | B, as a whole word */
    static const char *u[] = {"TB", "GB", "MB", "KB", "B"};
    for (size_t i = 0; i < sizeof u / sizeof *u; i++) {
        size_t l = strlen(u[i]);
        if (strncasecmp(p, u[i], l) == 0) {
            char n = p[l];
            if (!((n >= 'A' && n <= 'Z') || (n >= 'a' && n <= 'z') || (n >= '0' && n <= '9'))) return 1;
        }
    }
    return 0;
}

static int plain_int_end(const char *p) {              /* the digits just read are a bare byte count, not "12.5 GB" */
    p = sk(p);
    if (*p == '.' || *p == ',') return 0;
    return !is_unit_at(p);
}

static void parse_row(const char *table, const char *label, Stat *st) {
    memset(st, 0, sizeof *st);
    const char *p = strstr(table, label);
    if (!p) return;
    p += strlen(label);
    u64 v[4];
    for (int i = 0; i < 4; i++) if (!parse_size(&p, &v[i])) return;
    st->last = v[0]; st->today = v[1]; st->yesterday = v[2]; st->total = v[3];
}

static void parse_profile_text(const char *text, Prof *pr) {
    memset(pr, 0, sizeof *pr);
    const char *p;
    if ((p = strstr(text, "Профиль пользователя:"))) {
        p = sk(p + strlen("Профиль пользователя:")); size_t k = 0;
        while (*p && *p != ' ' && k < sizeof pr->username - 1) pr->username[k++] = *p++;
    }
    if ((p = strstr(text, "Рейтинг:"))) {
        p += strlen("Рейтинг:");
        if (parse_dbl(&p, &pr->rating)) pr->has_rating = 1;
    }
    if ((p = strstr(text, "После 2"))) {
        p += strlen("После 2");
        if (lit(&p, "GB скачанного")) pr->newbie = 1;
    }
    /* The formula appears twice: once with units, once in raw bytes. Only the bytes one counts. */
    for (const char *q = text; (q = strstr(q, "Всего отдано")); q += 3) {
        const char *c = q + strlen("Всего отдано"); u64 a, b, d, e;
        if (!parse_u64(&c, &a) || !plain_int_end(c)) continue;
        if (!lit(&c, "+") || !lit(&c, "на своих раздачах") || !parse_u64(&c, &b) || !plain_int_end(c)) continue;
        if (!lit(&c, "+") || !lit(&c, "бонусных") || !parse_u64(&c, &d) || !plain_int_end(c)) continue;
        if (!lit(&c, ")") || !lit(&c, "/") || !lit(&c, "Скачано") || !parse_u64(&c, &e) || !plain_int_end(c)) continue;
        pr->uploaded = a; pr->uploaded_own = b; pr->uploaded_bonus = d; pr->downloaded = e;
        break;
    }
    const char *table = strstr(text, "Посл. обновл.");
    if (table) {
        parse_row(table, "Скачано", &pr->down); parse_row(table, "Отдано", &pr->up);
        parse_row(table, "На своих", &pr->own);  parse_row(table, "Бонус", &pr->bonus);
    }
    if (!pr->downloaded) pr->downloaded = pr->down.total;
}

/* Downloaded as of the last stats update, plus today's: the number the site's own rules use.
 * (Same definition as the seeder's Profile.live_downloaded.) */
static u64 live_downloaded(const Prof *pr) {
    return (pr->downloaded > pr->down.total ? pr->downloaded : pr->down.total) + pr->down.today;
}

static u64 credited_upload(const Prof *pr) { return pr->uploaded + pr->uploaded_own + pr->uploaded_bonus; }

typedef struct { const char *name; int limit; } Tier;      /* limit < 0: unlimited */

/* The site's rating FAQ: how many .torrent files an account may fetch per day. Same table as
 * the seeder's app/limits.py. (Group members are unlimited; that can't be seen from here.) */
static Tier tier_of(const Prof *pr) {
    const u64 GB = 1073741824ULL, NEWBIE_CEILING = 2000000000ULL;
    if (pr->newbie || live_downloaded(pr) < NEWBIE_CEILING) return (Tier){"newbie", 5};
    double r = pr->has_rating ? pr->rating : 0.0;
    if (r >= 1.0) return credited_upload(pr) >= 100 * GB ? (Tier){"rating >= 1.0, 100 GB+ up", 100} : (Tier){"rating >= 1.0", 50};
    if (r >= 0.5) return (Tier){"rating 0.5-1.0", 50};
    if (r >= 0.3) return (Tier){"rating 0.3-0.5", 10};
    return (Tier){"rating < 0.3", 0};
}

/* ── the sidecar's own count of .torrent files fetched (rolling 24 hours) ── */

static pthread_mutex_t g_quota_mtx = PTHREAD_MUTEX_INITIALIZER;
static time_t g_site_refused_at = 0;                        /* when PornoLab itself last said "limit" */

static void data_path(char *out, size_t sz, const char *name) { snprintf(out, sz, "%s/%s", g_data, name); }

/* Count fetches in the last 24h and find the oldest of them. Caller holds g_quota_mtx. */
static int ledger_used(time_t now, time_t *oldest) {
    char path[600]; data_path(path, sizeof path, "dl_ledger.txt");
    FILE *f = fopen(path, "r"); int n = 0; *oldest = 0;
    if (!f) return 0;
    long long t;
    while (fscanf(f, "%lld", &t) == 1)
        if (now - (time_t)t < 86400) { n++; if (!*oldest || (time_t)t < *oldest) *oldest = (time_t)t; }
    fclose(f); return n;
}

static void ledger_add(time_t now) {
    pthread_mutex_lock(&g_quota_mtx);
    char path[600], tmp[620], total_path[600];
    data_path(path, sizeof path, "dl_ledger.txt"); snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *in = fopen(path, "r"), *out = fopen(tmp, "w");
    if (out) {
        long long t;
        while (in && fscanf(in, "%lld", &t) == 1) if (now - (time_t)t < 86400) fprintf(out, "%lld\n", t);
        fprintf(out, "%lld\n", (long long)now);
        fclose(out); rename(tmp, path);
    }
    if (in) fclose(in);
    data_path(total_path, sizeof total_path, "dl_total.txt");
    long long total = 0; FILE *tf = fopen(total_path, "r");
    if (tf) { if (fscanf(tf, "%lld", &total) != 1) total = 0; fclose(tf); }
    tf = fopen(total_path, "w"); if (tf) { fprintf(tf, "%lld\n", total + 1); fclose(tf); }
    pthread_mutex_unlock(&g_quota_mtx);
}

static long long ledger_lifetime(void) {
    char p[600]; data_path(p, sizeof p, "dl_total.txt");
    FILE *f = fopen(p, "r"); long long n = 0;
    if (f) { if (fscanf(f, "%lld", &n) != 1) n = 0; fclose(f); }
    return n;
}

static void note_site_refusal(time_t now) {
    pthread_mutex_lock(&g_quota_mtx); g_site_refused_at = now; pthread_mutex_unlock(&g_quota_mtx);
}

/* ── the profile, fetched with the logged-in session and cached for a few minutes ── */

#define PROFILE_TTL_S 600
static pthread_mutex_t g_prof_mtx = PTHREAD_MUTEX_INITIALIZER;
static Prof   g_prof;
static time_t g_prof_at = 0;
static char   g_uid[24];

static int logged_in_page(const Buf *b) {
    return b->buf && b->len && memmem(b->buf, b->len, "logout", 6) && !memmem(b->buf, b->len, "login_username", 14);
}

/* Fetch the profile page and (optionally) keep its text. Returns 1 on success; on failure
 * t_login_err or a short reason is set. Caller holds g_prof_mtx. */
static int fetch_profile(const char *user, const char *pass, Prof *out, Buf *text_out) {
    t_login_err[0] = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        Buf page = {0};
        if (!g_uid[0]) {                                   /* the profile id is in the top menu of any logged-in page */
            char url[512]; snprintf(url, sizeof url, "%s/forum/index.php", g_base);
            if (!session_get(url, &page, user, pass)) { free(page.buf); return 0; }
            const char *m = page.buf && page.len ? (const char *)memmem(page.buf, page.len, "profile.php?mode=viewprofile&", 29) : NULL;
            if (m) {
                m += 29; if (strncmp(m, "amp;", 4) == 0) m += 4;
                if (m[0] == 'u' && m[1] == '=') { size_t k = 0; m += 2; while (*m >= '0' && *m <= '9' && k < sizeof g_uid - 1) g_uid[k++] = *m++; g_uid[k] = 0; }
            }
            if (!g_uid[0]) {
                int dead = !logged_in_page(&page);
                free(page.buf);
                if (dead && attempt == 0 && !(g_cookie && *g_cookie)) { forget_session(); continue; }
                snprintf(t_login_err, sizeof t_login_err, dead ? "not logged in to PornoLab" : "could not find the profile link");
                return 0;
            }
            free(page.buf); page = (Buf){0};
        }
        char url[512]; snprintf(url, sizeof url, "%s/forum/profile.php?mode=viewprofile&u=%s", g_base, g_uid);
        if (!session_get(url, &page, user, pass)) { free(page.buf); return 0; }
        if (!logged_in_page(&page)) {
            free(page.buf);
            if (attempt == 0 && !(g_cookie && *g_cookie)) { forget_session(); continue; }
            snprintf(t_login_err, sizeof t_login_err, "not logged in to PornoLab");
            return 0;
        }
        Buf text = {0};
        html_to_text(page.buf, page.len, &text);
        free(page.buf);
        parse_profile_text((const char *)text.buf, out);
        if (text_out) { *text_out = text; } else free(text.buf);
        return 1;
    }
    return 0;
}

static int get_profile(const char *user, const char *pass, int force, Prof *out, time_t *age) {
    pthread_mutex_lock(&g_prof_mtx);
    time_t now = time(NULL);
    if (!force && g_prof_at && now - g_prof_at < PROFILE_TTL_S) {
        *out = g_prof; *age = now - g_prof_at; pthread_mutex_unlock(&g_prof_mtx); return 1;
    }
    Prof fresh;
    int ok = fetch_profile(user, pass, &fresh, NULL);
    if (ok) { g_prof = fresh; g_prof_at = now; *out = fresh; *age = 0; }
    pthread_mutex_unlock(&g_prof_mtx);
    return ok;
}

/* Where we stand today. */
typedef struct { Tier tier; int used; int left; long long wait_s; int refused_by_site; } Quota;

static Quota compute_quota(const Prof *pr, time_t now) {
    Quota q; q.tier = tier_of(pr);
    time_t oldest = 0;
    pthread_mutex_lock(&g_quota_mtx);
    q.used = ledger_used(now, &oldest);
    time_t refused = g_site_refused_at;
    pthread_mutex_unlock(&g_quota_mtx);
    q.refused_by_site = refused && now - refused < 3600;           /* the site said no recently: hold off an hour */
    q.left = q.tier.limit < 0 ? -1 : (q.used >= q.tier.limit ? 0 : q.tier.limit - q.used);
    q.wait_s = 0;
    if (q.tier.limit >= 0 && q.left == 0) q.wait_s = q.tier.limit == 0 ? 0 : (long long)(oldest + 86400 - now);
    if (q.refused_by_site) { q.left = 0; long long w = (long long)(refused + 3600 - now); if (w > q.wait_s) q.wait_s = w; }
    if (q.wait_s < 0) q.wait_s = 0;
    return q;
}

static void json_str(char *out, size_t sz, const char *s) {        /* username is the only free text; keep it safe */
    size_t k = 0; for (; *s && k + 2 < sz; s++) if (*s != '"' && *s != '\\' && (uint8_t)*s >= 0x20) out[k++] = *s;
    out[k] = 0;
}

static void quota_json(const Prof *pr, const Quota *q, time_t age, Buf *out) {
    char u[96], lim[24], left[24], rating[24], b[1800];
    json_str(u, sizeof u, pr->username);
    if (q->tier.limit < 0) snprintf(lim, sizeof lim, "null"); else snprintf(lim, sizeof lim, "%d", q->tier.limit);
    if (q->left < 0) snprintf(left, sizeof left, "null"); else snprintf(left, sizeof left, "%d", q->left);
    if (pr->has_rating) snprintf(rating, sizeof rating, "%.3f", pr->rating); else snprintf(rating, sizeof rating, "null");
    u64 dl_total = pr->downloaded > pr->down.total ? pr->downloaded : pr->down.total;
    snprintf(b, sizeof b,
        "{\"ok\":true,\"username\":\"%s\",\"tier\":\"%s\","
        "\"daily_limit\":%s,\"used_today\":%d,\"left\":%s,\"unlimited\":%s,"
        "\"next_slot_in_s\":%lld,\"refused_by_site_recently\":%s,"
        "\"downloaded_bytes\":%llu,\"downloaded_today_bytes\":%llu,\"downloaded_bytes_last_update\":%llu,"
        "\"uploaded_credited_bytes\":%llu,\"rating\":%s,"
        "\"torrent_files_fetched_total\":%lld,\"profile_age_s\":%lld,"
        "\"count_source\":\"sidecar\","
        "\"note\":\"used_today counts .torrent files fetched through this sidecar in the last 24h; "
        "downloads made elsewhere with the same account are not included. downloaded_bytes is the profile's "
        "live total (last update + today).\"}",
        u, q->tier.name, lim, q->used, left, q->tier.limit < 0 ? "true" : "false",
        q->wait_s, q->refused_by_site ? "true" : "false",
        live_downloaded(pr), pr->down.today, dl_total, credited_upload(pr), rating,
        ledger_lifetime(), (long long)age);
    buf_appendz(out, b);
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

/* Hand a real announce URL (which carries the passkey) to the external announce-proxy and get
 * back the URL to put in the torrent instead. Returns 1 and fills `out` on success. The real
 * URL is deliberately never logged. */
static int register_remote(const char *real, char *out, size_t outsz) {
    CURL *c = curl_easy_init();
    if (!c) return 0;
    char *eu = curl_easy_escape(c, real, 0);
    char *el = curl_easy_escape(c, t_label[0] ? t_label : "prowlarr", 0);
    char endpoint[1024], body[2048], hdr[320];
    snprintf(endpoint, sizeof endpoint, "%s/v1/register?format=text", g_annproxy);
    snprintf(body, sizeof body, "url=%s&label=%s", eu ? eu : "", el ? el : "");
    snprintf(hdr, sizeof hdr, "X-Api-Key: %s", g_annkey);
    struct curl_slist *h = curl_slist_append(NULL, hdr);
    Buf resp = {0};
    curl_easy_setopt(c, CURLOPT_URL,           endpoint);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS,    body);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER,    h);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,       15L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,     &resp);
    CURLcode rc = curl_easy_perform(c);
    long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    int ok = rc == CURLE_OK && code == 200 && resp.len > 8 && resp.len < outsz &&
             memcmp(resp.buf, "http", 4) == 0;
    if (ok) {
        memcpy(out, resp.buf, resp.len); out[resp.len] = 0;
        while (resp.len && (out[resp.len - 1] == '\n' || out[resp.len - 1] == '\r')) out[--resp.len] = 0;
    } else {
        logf("announce proxy registration failed (curl=%d http=%ld)", (int)rc, code);
    }
    curl_free(eu); curl_free(el); curl_slist_free_all(h); curl_easy_cleanup(c); free(resp.buf);
    return ok;
}

/* rewrite one announce URL bytes into proxy URL */
static void rewrite_url(BVal *b) {
    if (b->type != 's') return;
    if (b->s.n < 7) return;
    if (memcmp(b->s.p, "http://", 7) != 0 &&
        memcmp(b->s.p, "https://", 8) != 0) return;

    char orig[512]; size_t ol = b->s.n < 511 ? b->s.n : 511;
    memcpy(orig, b->s.p, ol); orig[ol] = 0;

    char newurl[640];
    if (g_annproxy && *g_annproxy) {
        if (!register_remote(orig, newurl, sizeof newurl)) {
            t_rewrite_failed = 1;       /* leave the URL alone; handle_dl refuses to return this torrent */
            return;
        }
    } else {
        char tok[16];
        /* register_url returns pointer into static array; copy before reuse */
        memcpy(tok, register_url(orig), 13);
        snprintf(newurl, sizeof newurl, "%s/ann?t=%s", g_self, tok);
    }

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
                       : code == 401 ? "Unauthorized"
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
    if (t_peer_loopback) return 1;       /* Prowlarr calls us on 127.0.0.1; the key is for everyone else */
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

    if (strcmp(id_str, "0") == 0) {          /* the quota row in the search results; nothing to download */
        respond(fd, 404, "text/plain", (uint8_t*)"this is the quota row, not a torrent", 37, NULL);
        return;
    }

    /* per-request credentials from Prowlarr indexer config (?u=…&p=…) */
    char req_user[256] = {0}, req_pass[256] = {0};
    qs_get(qs, "u", req_user, sizeof req_user);
    qs_get(qs, "p", req_pass, sizeof req_pass);

    if (g_quota_enforce) {
        /* Don't spend a request the site would refuse (or that would put the account at risk)
         * once today's allowance is used up. If the profile can't be read, let the fetch decide. */
        Prof qp; time_t age = 0, now = time(NULL);
        if (get_profile(*req_user ? req_user : g_user, *req_pass ? req_pass : g_pass, 0, &qp, &age)) {
            Quota q = compute_quota(&qp, now);
            if (q.tier.limit >= 0 && q.left == 0) {
                char msg[240], hdr[64];
                long long w = q.wait_s > 0 ? q.wait_s : 3600;
                if (q.tier.limit == 0)
                    snprintf(msg, sizeof msg, "PornoLab downloads are blocked for this account (%s)", q.tier.name);
                else if (q.refused_by_site)
                    snprintf(msg, sizeof msg, "PornoLab refused a download recently; holding off, retry in %lldm", (w + 59) / 60);
                else
                    snprintf(msg, sizeof msg, "PornoLab daily .torrent limit reached (%d of %d used); next slot in %lldh%02lldm",
                             q.used, q.tier.limit, w / 3600, (w % 3600) / 60);
                snprintf(hdr, sizeof hdr, "Retry-After: %lld\r\n", w);
                logf("download %s refused by quota: %s", id_str, msg);
                respond(fd, 429, "text/plain", (uint8_t*)msg, strlen(msg), hdr);
                return;
            }
        } else {
            logf("quota check skipped: %s", t_login_err[0] ? t_login_err : "profile unavailable");
        }
    }

    char url[512];
    snprintf(url, sizeof url, "%s/forum/dl.php?t=%s", g_base, id_str);

    Buf body = {0};
    int page = PG_OTHER;
    for (int attempt = 0; attempt < 2; attempt++) {
        t_login_err[0] = 0;
        if (!session_get(url, &body, req_user, req_pass)) {
            const char *why = t_login_err[0] ? t_login_err : "upstream error";
            respond(fd, t_login_err[0] ? 401 : 502, "text/plain", (uint8_t*)why, strlen(why), NULL);
            free(body.buf); return;
        }
        page = classify_page(body.buf, body.len);
        if (page == PG_TORRENT) break;
        /* A login form or captcha where the .torrent should be: the saved session is dead. Start
         * over once (unless the session came from PORNOLAB_COOKIE, which we can't renew). */
        if (attempt == 0 && (page == PG_LOGIN_FORM || page == PG_CAPTCHA) && !(g_cookie && *g_cookie)) {
            logf("saved PornoLab session is not valid any more; logging in again");
            forget_session(); free(body.buf); body = (Buf){0};
            continue;
        }
        break;
    }

    if (page == PG_TORRENT) ledger_add(time(NULL));         /* the site counted this fetch against the day */

    if (page != PG_TORRENT) {
        const char *msg; int code;
        if (g_cookie && *g_cookie && (page == PG_LOGIN_FORM || page == PG_CAPTCHA)) {
            code = 401; msg = "PORNOLAB_COOKIE is not logged in (expired?)";
        } else if (page == PG_CAPTCHA) {
            code = 401; msg = "PornoLab demands a captcha at login; set PORNOLAB_COOKIE or log in from a browser on this network first";
        } else if (page == PG_LOGIN_FORM) {
            code = 401; msg = "PornoLab did not accept the login (username/password)";
        } else if (body.buf && (memmem(body.buf, body.len < 4096 ? body.len : 4096, "limit", 5) ||
                                memmem(body.buf, body.len < 4096 ? body.len : 4096, "\xEB\xE8\xEC\xE8\xF2", 5) ||   /* "лимит" (cp1251) */
                                memmem(body.buf, body.len < 4096 ? body.len : 4096, "\xCB\xE8\xEC\xE8\xF2", 5))) {   /* "Лимит" */
            code = 429; msg = "PornoLab download limit reached";
            note_site_refusal(time(NULL));
        } else {
            code = 503; msg = "PornoLab returned a page instead of a .torrent";
        }
        logf("download %s refused: %s (page %d, %zu bytes)", id_str, msg, page, body.len);
        respond(fd, code, "text/plain", (uint8_t*)msg, strlen(msg), NULL);
        free(body.buf); return;
    }

    snprintf(t_label, sizeof t_label, "%s", *req_user ? req_user : (*g_user ? g_user : "prowlarr"));
    t_rewrite_failed = 0;
    size_t outlen = 0;
    uint8_t *out = rewrite_torrent(body.buf, body.len, &outlen);
    free(body.buf);
    if (out && t_rewrite_failed) {      /* never hand back a torrent that still has the real announce URL */
        free(out);
        respond(fd, 502, "text/plain", (uint8_t*)"announce proxy unavailable", 26, NULL);
        return;
    }
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

/* GET /quota[?refresh=1][&u=&p=]   today's allowance and the profile's downloaded total, as JSON
 * GET /quota/dump                   save the profile page's text to <data>/profile_dump.txt (diagnostics) */
static void handle_quota(int fd, const char *qs, const char *apikey_hdr, int dump) {
    (void)apikey_hdr;
    if (!t_peer_loopback) { respond(fd, 403, "text/plain", (uint8_t*)"forbidden", 9, NULL); return; }
    char u[256] = {0}, p[256] = {0}, r[8] = {0};
    qs_get(qs, "u", u, sizeof u); qs_get(qs, "p", p, sizeof p); qs_get(qs, "refresh", r, sizeof r);
    const char *user = *u ? u : g_user, *pass = *p ? p : g_pass;
    Prof pr; time_t age = 0, now = time(NULL);
    int ok;
    Buf text = {0};
    if (dump) {
        pthread_mutex_lock(&g_prof_mtx);
        ok = fetch_profile(user, pass, &pr, &text);
        pthread_mutex_unlock(&g_prof_mtx);
    } else {
        ok = get_profile(user, pass, r[0] == '1', &pr, &age);
    }
    if (!ok) {
        char msg[300]; const char *why = t_login_err[0] ? t_login_err : "could not read the PornoLab profile";
        int n = snprintf(msg, sizeof msg, "{\"ok\":false,\"error\":\"%s\"}", why);
        respond(fd, t_login_err[0] ? 401 : 502, "application/json", (uint8_t*)msg, (size_t)n, NULL);
        free(text.buf); return;
    }
    if (dump) {
        char path[600], reply[700]; data_path(path, sizeof path, "profile_dump.txt");
        FILE *f = fopen(path, "w");
        if (f) { fchmod(fileno(f), 0600); fwrite(text.buf, 1, text.len ? text.len - 1 : 0, f); fclose(f); }
        int n = snprintf(reply, sizeof reply, "wrote %zu bytes of profile text to %s\n", text.len ? text.len - 1 : 0, path);
        respond(fd, f ? 200 : 502, "text/plain", (uint8_t*)reply, (size_t)n, NULL);
        free(text.buf); return;
    }
    Quota q = compute_quota(&pr, now);
    Buf j = {0};
    quota_json(&pr, &q, age, &j);
    respond(fd, 200, "application/json", j.buf, j.len, NULL);
    free(j.buf);
}

static void human_size(u64 b, char *out, size_t sz) {
    const char *u[] = {"B", "KB", "MB", "GB", "TB"}; double v = (double)b; int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    if (i == 0) snprintf(out, sz, "%llu B", b); else snprintf(out, sz, "%.2f %s", v, u[i]);
}

/* GET /quota-row[?u=&p=]  -- the indexer's second search path.
 *
 * Prowlarr merges this page's rows into the results of every search, so the account's daily
 * allowance travels in the same reply (and under the same Prowlarr API key) as the releases.
 * It is one fake row laid out like a tracker.php row, so the definition's own selectors read it:
 *   title    a human sentence plus key=value pairs (left=3 limit=5 used=2 downloaded_bytes=...)
 *   seeders  downloads left today        leechers  daily limit        grabs  used today
 *   size     the profile's live downloaded total, in bytes
 *   date     now (unix)
 * Its download link is topic 0, which /dl refuses. If the profile can't be read the row still
 * comes back, saying why, so a search never fails because of the quota. */
static void handle_quota_row(int fd, const char *qs) {
    if (!t_peer_loopback) { respond(fd, 403, "text/plain", (uint8_t*)"forbidden", 9, NULL); return; }
    char u[256] = {0}, p[256] = {0};
    qs_get(qs, "u", u, sizeof u); qs_get(qs, "p", p, sizeof p);
    Prof pr; time_t age = 0, now = time(NULL);
    char title[900]; long long left = 0, limit = 0, used = 0; u64 size = 0;
    if (get_profile(*u ? u : g_user, *p ? p : g_pass, 0, &pr, &age)) {
        Quota q = compute_quota(&pr, now);
        char dl[32]; size = live_downloaded(&pr); human_size(size, dl, sizeof dl);
        limit = q.tier.limit; used = q.used; left = q.left;
        char lim_txt[40], left_txt[40];
        if (q.tier.limit < 0) { snprintf(lim_txt, sizeof lim_txt, "unlimited"); snprintf(left_txt, sizeof left_txt, "unlimited"); }
        else { snprintf(lim_txt, sizeof lim_txt, "%d", q.tier.limit); snprintf(left_txt, sizeof left_txt, "%d", q.left); }
        snprintf(title, sizeof title,
            "PornoLab quota: %s of %s .torrent files left today (used %d) | downloaded %s | tier: %s | "
            "left=%lld limit=%lld used=%d downloaded_bytes=%llu next_slot_s=%lld",
            left_txt, lim_txt, q.used, dl, q.tier.name, left, limit, q.used, size, q.wait_s);
        if (q.tier.limit < 0) { left = 0; limit = 0; }
    } else {
        snprintf(title, sizeof title, "PornoLab quota: unavailable (%s) | left=unknown",
                 t_login_err[0] ? t_login_err : "profile could not be read");
    }
    /* ASCII only, and nothing that needs escaping beyond '&' and '<' (none are produced above). */
    char html[2600];
    int n = snprintf(html, sizeof html,
        "<html><body><div class=\"topmenu\"><a onclick=\"return logout()\">logout</a></div>"
        "<table id=\"tor-tbl\"><tbody><tr>"
        "<td></td><td><a class=\"f\" href=\"tracker.php?f=1670\">quota</a></td>"
        "<td><a class=\"tLink\" href=\"viewtopic.php?t=0\">%s</a></td><td></td>"
        "<td><a class=\"tr-dl\" href=\"dl.php?t=0\">quota</a></td>"
        "<td><u>%llu</u></td><td class=\"seedmed\"><b>%lld</b></td><td class=\"leechmed\"><b>%lld</b></td>"
        "<td>%lld</td><td></td><td><u>%lld</u></td></tr></tbody></table></body></html>",
        title, size, left < 0 ? 0 : left, limit, used, (long long)now);
    respond(fd, 200, "text/html; charset=windows-1251", (uint8_t*)html, (size_t)n, NULL);
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

typedef struct { int fd; int loopback; } ConnArg;

static void *handle_conn(void *arg) {
    int fd = ((ConnArg *)arg)->fd;
    t_peer_loopback = ((ConnArg *)arg)->loopback;
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
    } else if (strcmp(raw_path, "/quota") == 0 || strcmp(raw_path, "/quota/dump") == 0) {
        handle_quota(fd, qs, apikey_hdr[0] ? apikey_hdr : NULL, strcmp(raw_path, "/quota/dump") == 0);
    } else if (strcmp(raw_path, "/quota-row") == 0) {
        handle_quota_row(fd, qs);
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
    g_cookie   = getenv("PORNOLAB_COOKIE")     ?: "";
    g_prowlarr_dir = getenv("PROWLARR_CONFIG_DIR") ?: "/config";
    g_use_prowlarr_session = !(getenv("PROWLARR_SESSION") && strcmp(getenv("PROWLARR_SESSION"), "0") == 0);
    g_ua_override = getenv("PORNOLAB_USER_AGENT") ?: "";
    g_quota_enforce = !(getenv("QUOTA_ENFORCE") && strcmp(getenv("QUOTA_ENFORCE"), "0") == 0);
    g_annproxy = getenv("ANNOUNCE_PROXY_URL") ?: "";
    g_annkey   = getenv("ANNOUNCE_PROXY_KEY") ?: "";
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
        struct sockaddr_in peer; socklen_t plen = sizeof peer;
        int fd = accept(srv, (struct sockaddr *)&peer, &plen);
        if (fd < 0) continue;
        ConnArg *a = malloc(sizeof *a); a->fd = fd;
        a->loopback = (ntohl(peer.sin_addr.s_addr) >> 24) == 127;
        pthread_t t;
        pthread_attr_t attr; pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&t, &attr, handle_conn, a);
        pthread_attr_destroy(&attr);
    }
}
