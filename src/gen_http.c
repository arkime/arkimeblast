#include "gen_http.h"
#include "net_utils.h"

#include <string.h>
#include <stdio.h>

/* --- Realistic header value pools --- */

static const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "Apache-HttpClient/4.5.14 (Java/17.0.9)",
    "Wget/1.21.4",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; ARM; Surface Pro X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.61",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Avast/120.0.0.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 12; moto g power (2022)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A.240105.002)",
    "okhttp/4.12.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    "PostmanRuntime/7.36.0",
    "axios/1.6.2",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
};
#define NUM_USER_AGENTS (sizeof(user_agents) / sizeof(user_agents[0]))

static const char *hosts[] = {
    "www.example.com", "cdn.example.com", "api.service.io",
    "static.assets.net", "app.dashboard.io", "www.news-site.com",
    "store.shopping.com", "img.cdn.provider.net", "docs.platform.dev",
    "search.engine.com", "mail.provider.org", "cloud.storage.io",
    "video.streaming.tv", "social.media.com", "blog.tech.io",
    "login.auth.service.com", "payments.gateway.io", "maps.geo.service.com",
    "analytics.tracking.io", "fonts.cdn.service.net", "music.stream.fm",
    "weather.forecast.io", "news.feed.org", "wiki.knowledge.com",
    "forum.community.io", "games.online.gg", "files.share.cloud",
    "photos.gallery.app", "calendar.schedule.io", "chat.messaging.app",
};
#define NUM_HOSTS (sizeof(hosts) / sizeof(hosts[0]))

static const char *paths[] = {
    "/", "/index.html", "/api/v2/users", "/api/v1/data",
    "/images/logo.png", "/css/style.css", "/js/app.js",
    "/search?q=performance+testing", "/login", "/dashboard",
    "/api/v3/events?limit=50", "/favicon.ico", "/robots.txt",
    "/products/12345", "/cart/checkout", "/api/health",
    "/static/fonts/roboto.woff2", "/download/report.pdf",
    "/api/v2/sessions", "/settings/profile", "/about",
    "/contact", "/terms", "/privacy", "/feed.xml",
    "/api/v1/metrics?from=1704067200&to=1704153600",
    "/images/hero-banner.jpg", "/videos/intro.mp4",
    "/api/graphql", "/webhooks/callback",
};
#define NUM_PATHS (sizeof(paths) / sizeof(paths[0]))

static const char *accept_values[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    "text/css,*/*;q=0.1",
    "application/javascript, */*;q=0.8",
    "application/json",
};
#define NUM_ACCEPTS (sizeof(accept_values) / sizeof(accept_values[0]))

static const char *accept_languages[] = {
    "en-US,en;q=0.9", "en-GB,en;q=0.9", "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8", "pt-BR,pt;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8", "ko-KR,ko;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8", "ru-RU,ru;q=0.9,en;q=0.8",
    "nl-NL,nl;q=0.9,en;q=0.8", "en-US,en;q=0.5",
    "en-AU,en;q=0.9", "en-CA,en;q=0.9",
};
#define NUM_ACCEPT_LANGS (sizeof(accept_languages) / sizeof(accept_languages[0]))

static const char *accept_encodings[] = {
    "gzip, deflate, br", "gzip, deflate, br, zstd",
    "gzip, deflate", "gzip", "br", "identity",
    "gzip, deflate, br, zstd, snappy",
};
#define NUM_ACCEPT_ENCS (sizeof(accept_encodings) / sizeof(accept_encodings[0]))

static const char *referers[] = {
    "https://www.google.com/", "https://www.bing.com/",
    "https://duckduckgo.com/", "https://www.reddit.com/",
    "https://news.ycombinator.com/", "https://twitter.com/",
    "https://www.facebook.com/", "https://github.com/",
    "https://stackoverflow.com/", "https://www.linkedin.com/",
};
#define NUM_REFERERS (sizeof(referers) / sizeof(referers[0]))

static const char *servers[] = {
    "nginx/1.24.0", "Apache/2.4.58 (Ubuntu)", "cloudflare",
    "Microsoft-IIS/10.0", "nginx", "Apache",
    "gunicorn/21.2.0", "LiteSpeed", "openresty/1.25.3.1",
};
#define NUM_SERVERS (sizeof(servers) / sizeof(servers[0]))

static const char *content_types_resp[] = {
    "text/html; charset=utf-8",
    "application/json; charset=utf-8",
    "application/json",
    "text/plain; charset=utf-8",
    "image/png",
    "image/jpeg",
    "text/css; charset=utf-8",
    "application/javascript; charset=utf-8",
    "application/xml; charset=utf-8",
    "application/octet-stream",
};
#define NUM_CONTENT_TYPES (sizeof(content_types_resp) / sizeof(content_types_resp[0]))

int gen_http_request(uint8_t *buf, size_t bufsize, uint64_t *rng)
{
    const char *method = (rng_range(rng, 100) < 80) ? "GET" : "POST";
    const char *path = paths[rng_range(rng, NUM_PATHS)];
    const char *host = hosts[rng_range(rng, NUM_HOSTS)];
    const char *ua = user_agents[rng_range(rng, NUM_USER_AGENTS)];
    const char *accept = accept_values[rng_range(rng, NUM_ACCEPTS)];
    const char *lang = accept_languages[rng_range(rng, NUM_ACCEPT_LANGS)];
    const char *enc = accept_encodings[rng_range(rng, NUM_ACCEPT_ENCS)];
    const char *conn = (rng_range(rng, 100) < 85) ? "keep-alive" : "close";

    int n = snprintf((char *)buf, bufsize,
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: %s\r\n"
        "Accept-Language: %s\r\n"
        "Accept-Encoding: %s\r\n"
        "Connection: %s\r\n",
        method, path, host, ua, accept, lang, enc, conn);

    /* Optional headers */
    if (rng_range(rng, 100) < 40) {
        n += snprintf((char *)buf + n, bufsize - n,
            "Referer: %s\r\n", referers[rng_range(rng, NUM_REFERERS)]);
    }
    if (rng_range(rng, 100) < 30) {
        n += snprintf((char *)buf + n, bufsize - n,
            "Cookie: session_id=%08x; pref=lang_%s\r\n",
            (uint32_t)rng_next(rng),
            accept_languages[rng_range(rng, NUM_ACCEPT_LANGS)]);
    }
    if (rng_range(rng, 100) < 20) {
        const char *cache_vals[] = {"no-cache", "max-age=0", "no-store"};
        n += snprintf((char *)buf + n, bufsize - n,
            "Cache-Control: %s\r\n", cache_vals[rng_range(rng, 3)]);
    }

    n += snprintf((char *)buf + n, bufsize - n, "\r\n");
    return n;
}

int gen_http_response(uint8_t *buf, size_t bufsize, uint64_t *rng,
                      size_t *total_body_size)
{
    /* Pick status code */
    int status;
    const char *status_text;
    uint32_t r = rng_range(rng, 100);
    if (r < 85) { status = 200; status_text = "OK"; }
    else if (r < 90) { status = 301; status_text = "Moved Permanently"; }
    else if (r < 93) { status = 304; status_text = "Not Modified"; }
    else if (r < 97) { status = 404; status_text = "Not Found"; }
    else { status = 500; status_text = "Internal Server Error"; }

    const char *server = servers[rng_range(rng, NUM_SERVERS)];
    const char *ct = content_types_resp[rng_range(rng, NUM_CONTENT_TYPES)];

    /* Body size: 100 bytes to 100KB */
    *total_body_size = 100 + rng_range(rng, 102300);
    if (status == 304)
        *total_body_size = 0;

    int n = snprintf((char *)buf, bufsize,
        "HTTP/1.1 %d %s\r\n"
        "Server: %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Date: Sat, 21 Feb 2026 12:00:00 GMT\r\n",
        status, status_text, server, ct, *total_body_size);

    if (rng_range(rng, 100) < 40) {
        n += snprintf((char *)buf + n, bufsize - n,
            "X-Request-Id: %016lx\r\n", rng_next(rng));
    }
    if (rng_range(rng, 100) < 25) {
        n += snprintf((char *)buf + n, bufsize - n,
            "Set-Cookie: tracking=%08x; Path=/; HttpOnly\r\n",
            (uint32_t)rng_next(rng));
    }
    if (status == 301) {
        n += snprintf((char *)buf + n, bufsize - n,
            "Location: https://%s%s\r\n",
            hosts[rng_range(rng, NUM_HOSTS)],
            paths[rng_range(rng, NUM_PATHS)]);
    }

    n += snprintf((char *)buf + n, bufsize - n, "\r\n");
    return n;
}

int gen_http_body_chunk(uint8_t *buf, size_t bufsize, size_t offset,
                        size_t total_size, uint64_t *rng)
{
    size_t remaining = total_size - offset;
    size_t chunk = remaining;
    if (chunk > bufsize)
        chunk = bufsize;

    /* Fill with printable ASCII (8 bytes per RNG call, not one) */
    rng_fill_printable(buf, chunk, rng);

    return (int)chunk;
}
