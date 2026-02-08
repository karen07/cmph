#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <cmph.h>
#include <curl/curl.h>

static uint32_t g_seed32 = 0;

static void die(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p) {
        die("out of memory");
    }
    return p;
}

static size_t chomp_eol(char *s)
{
    if (!s) {
        return 0;
    }
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
    return n;
}

static int parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s) {
        return -1;
    }
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (!end || *end) {
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

static inline uint32_t rd32u(const void *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static inline uint32_t murmur3_32(const void *key, size_t len, uint32_t seed)
{
    const uint8_t *data = (const uint8_t *)key;
    const int nblocks = (int)(len / 4);
    uint32_t h1 = seed;
    const uint32_t c1 = 0xcc9e2d51u, c2 = 0x1b873593u;
    for (int i = 0; i < nblocks; i++) {
        uint32_t k1 = rd32u(data + i * 4);
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;
        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5u + 0xe6546b64u;
    }
    const uint8_t *tail = data + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3u) {
    case 3:
        k1 ^= (uint32_t)tail[2] << 16;
        /* fall through */
    case 2:
        k1 ^= (uint32_t)tail[1] << 8;
        /* fall through */
    case 1:
        k1 ^= (uint32_t)tail[0];
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;
        h1 ^= k1;
        /* fall through */
    }
    h1 ^= (uint32_t)len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6bu;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35u;
    h1 ^= h1 >> 16;
    return h1;
}

static uint64_t splitmix64(uint64_t *st)
{
    uint64_t z = (*st += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static inline uint32_t tag32(const char *s, size_t len)
{
    return murmur3_32(s, len, g_seed32);
}

struct membuf {
    char *data;
    size_t size;
};

static size_t curl_write_cb(void *contents, size_t sz, size_t nm, void *userp)
{
    size_t n = sz * nm;
    struct membuf *mb = (struct membuf *)userp;
    char *p = (char *)realloc(mb->data, mb->size + n + 1);
    if (!p) {
        return 0;
    }
    mb->data = p;
    memcpy(mb->data + mb->size, contents, n);
    mb->size += n;
    mb->data[mb->size] = 0;
    return n;
}

static int fetch_url(const char *url, char **out_data, size_t *out_len)
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }
    struct membuf mb = (struct membuf){ 0 };
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &mb);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/8.x");
    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || code < 200 || code >= 300) {
        free(mb.data);
        return -1;
    }
    *out_data = mb.data;
    *out_len = mb.size;
    return 0;
}

struct strvec {
    char **v;
    size_t n;
    size_t cap;
};

static void sv_push(struct strvec *sv, char *s)
{
    if (sv->n == sv->cap) {
        size_t nc = sv->cap ? sv->cap * 2 : 1024;
        char **p = (char **)realloc(sv->v, nc * sizeof(char *));
        if (!p) {
            die("out of memory");
        }
        sv->v = p;
        sv->cap = nc;
    }
    sv->v[sv->n++] = s;
}

static size_t split_lines_inplace(char *buf, size_t blen, char ***out_lines)
{
    struct strvec sv = { 0 };
    size_t i = 0;

    while (i < blen) {
        while (i < blen && (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '\0')) {
            i++;
        }
        if (i >= blen)
            break;

        char *start = &buf[i];

        while (i < blen && buf[i] != '\n' && buf[i] != '\r') {
            i++;
        }

        size_t len = (size_t)(&buf[i] - start);

        if (i < blen) {
            buf[i] = '\0';
            i++;
        }

        if (len > 0) {
            sv_push(&sv, start);
        }
    }

    *out_lines = sv.v;
    return sv.n;
}

static cmph_t *build_mph_vec(char **lines, size_t nlines)
{
    cmph_io_adapter_t *src = cmph_io_vector_adapter(lines, (cmph_uint32)nlines);
    if (!src) {
        die("cmph_io_vector_adapter failed");
    }
    cmph_config_t *cfg = cmph_config_new(src);
    if (!cfg) {
        die("cmph_config_new failed");
    }
    cmph_config_set_algo(cfg, CMPH_BDZ);
    cmph_t *mph = cmph_new(cfg);
    if (!mph) {
        die("cmph_new failed (duplicate/invalid keys?)");
    }
    cmph_config_destroy(cfg);
    cmph_io_vector_adapter_destroy(src);
    return mph;
}

static uint32_t *build_table_vec(char **lines, size_t nlines, cmph_t *mph, uint32_t *out_n,
                                 char ***out_keys)
{
    uint32_t n = cmph_size(mph);
    if (n == 0) {
        die("cmph_size returned 0");
    }
    if (out_n) {
        *out_n = n;
    }
    uint32_t *tab = (uint32_t *)xmalloc((size_t)n * sizeof(uint32_t));
    memset(tab, 0, (size_t)n * sizeof(uint32_t));
    uint8_t *mark = (uint8_t *)calloc((size_t)n, 1);
    if (!mark) {
        die("out of memory");
    }
    char **keys = (char **)calloc((size_t)n, sizeof(char *));
    if (!keys) {
        die("out of memory");
    }
    for (size_t i = 0; i < nlines; i++) {
        size_t len = chomp_eol(lines[i]);
        if (!len) {
            continue;
        }
        uint32_t idx = cmph_search(mph, lines[i], (uint32_t)len);
        uint32_t want = tag32(lines[i], len);
        if (!mark[idx]) {
            tab[idx] = want;
            keys[idx] = strdup(lines[i]);
            if (!keys[idx]) {
                die("out of memory");
            }
            mark[idx] = 1;
        } else {
            if (tab[idx] != want) {
                fprintf(stderr, "[warn] collision at idx=%u: \"%s\"\n", idx, lines[i]);
            }
        }
    }
    free(mark);
    if (out_keys) {
        *out_keys = keys;
    } else {
        for (uint32_t i = 0; i < n; i++) {
            free(keys[i]);
        }
        free(keys);
    }
    return tab;
}

static int selftest_vec(cmph_t *mph, const uint32_t *tab, char **lines, size_t nlines)
{
    unsigned long long total = 0, ok = 0, bad = 0;
    for (size_t i = 0; i < nlines; i++) {
        size_t len = chomp_eol(lines[i]);
        if (!len) {
            continue;
        }
        total++;
        uint32_t idx = cmph_search(mph, lines[i], (uint32_t)len);
        uint32_t want = tag32(lines[i], len);
        if (tab[idx] == want) {
            ok++;
        } else {
            bad++;
            if (bad <= 10) {
                fprintf(stderr, "[selftest] mismatch at line=%llu idx=%u key=\"%s\"\n", ok + bad,
                        idx, lines[i]);
            }
        }
    }
    if (bad == 0) {
        fprintf(stderr, "[selftest] OK: %llu / %llu lines\n", ok, total);
        return 0;
    }
    fprintf(stderr, "[selftest] FAIL: mismatches=%llu ok=%llu total=%llu\n", bad, ok, total);
    return 1;
}

static void random_probe(cmph_t *mph, const uint32_t *tab, char **keys, uint64_t seed,
                         uint64_t millions)
{
    const uint64_t COUNT = millions * 1000000ull;
    if (COUNT == 0) {
        fprintf(stderr, "[rand] skipped (count=0)\n");
        return;
    }
    static const char ALPH[] = "abcdefghijklmnopqrstuvwxyz0123456789.-";
    const size_t AN = sizeof(ALPH) - 1;
    char buf[256];
    unsigned long long hits = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    fprintf(stderr, "[rand] count=%llu (millions=%llu)\n", (unsigned long long)COUNT,
            (unsigned long long)millions);
    uint64_t rng = seed;
    for (uint64_t i = 0; i < COUNT; i++) {
        size_t len = 5 + (size_t)(splitmix64(&rng) % 240);
        for (size_t j = 0; j < len; j++) {
            buf[j] = ALPH[splitmix64(&rng) % AN];
        }
        buf[len] = 0;
        uint32_t idx = cmph_search(mph, buf, (uint32_t)len);
        uint32_t want = tag32(buf, len);
        if (tab[idx] == want) {
            const char *k = keys[idx];
            if (!(k && strlen(k) == len && memcmp(k, buf, len) == 0)) {
                hits++;
            }
        }
        if (((i + 1) % 1000000ull) == 0ull) {
            fprintf(stderr, "[rand] progress: %10llu / %llu\r", (unsigned long long)(i + 1),
                    (unsigned long long)COUNT);
            fflush(stderr);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dur = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    double qps = dur > 0 ? (double)COUNT / dur : 0.0;
    double obs_fpr = (double)hits / (double)COUNT;
    double exp_fpr = 1.0 / 4294967296.0;
    double ratio = exp_fpr > 0 ? obs_fpr / exp_fpr : 0.0;
    fprintf(stderr, "\n[rand] tested=%llu, present=%llu, fpr=%.12g, expected=%.12g, ratio=%.3fx\n",
            (unsigned long long)COUNT, (unsigned long long)hits, obs_fpr, exp_fpr, ratio);
    fprintf(stderr, "[rand] seed=%llu, time=%.3fs, qps=%.0f\n", (unsigned long long)seed, dur, qps);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <url> [--rand M]\n", prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    const char *url = argv[1];
    uint64_t rand_m = 10;
    if (argc > 2) {
        if (strcmp(argv[2], "--rand") == 0 && argc > 3) {
            if (parse_u64(argv[3], &rand_m) != 0) {
                usage(argv[0]);
                return 2;
            }
        } else {
            if (strncmp(argv[2], "--rand=", 7) == 0) {
                if (parse_u64(argv[2] + 7, &rand_m) != 0) {
                    usage(argv[0]);
                    return 2;
                }
            }
        }
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    char *buf = NULL;
    size_t blen = 0;
    if (fetch_url(url, &buf, &blen) != 0) {
        fprintf(stderr, "curl fetch failed for URL: %s\n", url);
        curl_global_cleanup();
        return 2;
    }
    char **lines = NULL;
    size_t nlines = split_lines_inplace(buf, blen, &lines);
    if (nlines == 0) {
        fprintf(stderr, "no input lines\n");
        free(buf);
        curl_global_cleanup();
        return 2;
    }
    cmph_t *mph = build_mph_vec(lines, nlines);
    uint64_t s0 = (uint64_t)time(NULL) ^ (uint64_t)(uintptr_t)&s0;
    g_seed32 = (uint32_t)splitmix64(&s0);
    uint32_t n = 0;
    char **keys = NULL;
    uint32_t *tab = build_table_vec(lines, nlines, mph, &n, &keys);
    fprintf(stderr, "[ready] keys=%u, fp_table=%.2f MiB\n", n,
            (double)((size_t)n * sizeof(uint32_t)) / 1048576.0);
    int st = selftest_vec(mph, tab, lines, nlines);
    uint64_t rng_seed = splitmix64(&s0);
    random_probe(mph, tab, keys, rng_seed, rand_m);
    for (uint32_t i = 0; i < n; i++) {
        free(keys[i]);
    }
    free(keys);
    free(tab);
    cmph_destroy(mph);
    free(lines);
    free(buf);
    curl_global_cleanup();
    return st ? 1 : 0;
}
