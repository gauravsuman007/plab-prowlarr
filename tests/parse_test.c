/* Parser/tier checks against the profile page's real layout (tests/profile_sample.txt is its visible
 * text with the name and dates replaced). Build and run from the repo root:
 *   cc -o /tmp/parse_test tests/parse_test.c -lcurl -lpthread -lsqlite3 && /tmp/parse_test            */
#define main proxy_main
#include "../proxy.c"
#undef main
#include <assert.h>

static void check(int ok, const char *what) { printf("%s %s\n", ok ? "ok  " : "FAIL", what); if (!ok) exit(1); }

int main(void) {
    /* 1. the real layout, as text */
    FILE *f = fopen("tests/profile_sample.txt", "rb"); assert(f);
    static char text[65536]; size_t n = fread(text, 1, sizeof text - 1, f); text[n] = 0; fclose(f);
    Prof p; parse_profile_text(text, &p);
    check(strcmp(p.username, "testuser") == 0, "username");
    check(p.has_rating && p.rating > 1.65 && p.rating < 1.67, "rating 1.66");
    check(p.uploaded == 10236714516ULL && p.downloaded == 6155304454ULL, "raw-byte formula (the line followed by 'FAQ')");
    check(p.down.today == (u64)(450.5 * 1048576) && p.down.total == (u64)(5.73 * 1073741824.0), "download row: today 450.5 MB, total 5.73 GB");
    check(!p.newbie, "not a newbie");
    check(live_downloaded(&p) == 6155304454ULL + p.down.today, "live downloaded = max(formula, table total) + today");
    Tier t = tier_of(&p);
    check(t.limit == 50 && strcmp(t.name, "rating >= 1.0") == 0, "tier: rating >= 1.0, 9.5 GB up -> 50 a day");

    /* 2. a stray NUL in the page (the real one has one before the profile section) must not hide the rest */
    const char html[] = "<html><body>head\0junk <h1>\xCF\xF0\xEE\xF4\xE8\xEB\xFC \xEF\xEE\xEB\xFC\xE7\xEE\xE2\xE0\xF2\xE5\xEB\xFF: bob</h1></body></html>";
    Buf b = {0}; html_to_text((const uint8_t *)html, sizeof html - 1, &b);
    check(strstr((char *)b.buf, "bob") != NULL, "text after a NUL byte survives html_to_text (cp1251 label decoded)");
    free(b.buf);

    /* 3. tiers */
    Prof q; memset(&q, 0, sizeof q);
    q.newbie = 1; check(tier_of(&q).limit == 5, "newbie banner -> 5");
    memset(&q, 0, sizeof q); q.downloaded = 1500000000ULL; q.has_rating = 1; q.rating = 9; check(tier_of(&q).limit == 5, "under 2 GB downloaded -> 5");
    memset(&q, 0, sizeof q); q.downloaded = 5000000000ULL; q.has_rating = 1; q.rating = 0.4; check(tier_of(&q).limit == 10, "rating 0.4 -> 10");
    q.rating = 0.2; check(tier_of(&q).limit == 0, "rating 0.2 -> blocked");
    q.rating = 2; q.uploaded = 101 * 1073741824ULL; check(tier_of(&q).limit == 100, "rating 2, 100 GB+ up -> 100");
    printf("all parser checks passed\n");
    return 0;
}
