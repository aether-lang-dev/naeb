/* The egress proxy's own name resolution and address vetting
 * (docs/naeb/adr/0001, "Network egress"): every address a name resolves
 * to, as text, so the proxy can refuse local and private ones and connect
 * to the vetted address itself, with no second resolution. A STAND-IN for
 * a std.net resolver that returns addresses
 * (asks/aether-fs-descriptor-paths.md). */
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* Every address `host` resolves to, numeric, one per line, IPv4 first as
 * getaddrinfo orders them; "" when it does not resolve. */
const char *nibnet_resolve(const char *host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return strdup("");
    size_t cap = 256, len = 0;
    char *out = malloc(cap);
    if (!out) { freeaddrinfo(res); return strdup(""); }
    out[0] = 0;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        char buf[INET6_ADDRSTRLEN];
        const void *src = NULL;
        if (a->ai_family == AF_INET) src = &((struct sockaddr_in *)a->ai_addr)->sin_addr;
        else if (a->ai_family == AF_INET6) src = &((struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
        if (!src || !inet_ntop(a->ai_family, src, buf, sizeof buf)) continue;
        size_t n = strlen(buf);
        if (strstr(out, buf)) continue;
        if (len + n + 2 > cap) {
            cap = (len + n + 2) * 2;
            char *g = realloc(out, cap);
            if (!g) break;
            out = g;
        }
        memcpy(out + len, buf, n);
        len += n;
        out[len++] = '\n';
        out[len] = 0;
    }
    freeaddrinfo(res);
    return out;
}

static const char *vet4_(uint32_t a) {
    uint8_t b0 = a >> 24, b1 = (a >> 16) & 0xff;
    if (b0 == 0) return "unspecified";
    if (b0 == 127) return "loopback";
    if (b0 == 10 || (b0 == 172 && (b1 & 0xf0) == 16) || (b0 == 192 && b1 == 168)) return "private";
    if (b0 == 100 && (b1 & 0xc0) == 64) return "shared (carrier-grade NAT)";
    if (b0 == 169 && b1 == 254) return "link-local";
    if (b0 >= 224 && b0 <= 239) return "multicast";
    if (b0 >= 240) return "reserved";
    return "";
}

/* Why the proxy does not connect to `addr` (numeric) unless the policy
 * names that address: "loopback", "private", "link-local", "unspecified",
 * "multicast", ... (IPv4-mapped and NAT64 forms by the address they
 * carry); "" for an ordinary public address; "not an address" otherwise. */
const char *nibnet_vet(const char *addr) {
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, addr, &v4) == 1) return vet4_(ntohl(v4.s_addr));
    if (inet_pton(AF_INET6, addr, &v6) != 1) return "not an address";
    const uint8_t *b = v6.s6_addr;
    static const uint8_t zero[16] = {0};
    if (memcmp(b, zero, 16) == 0) return "unspecified";
    if (memcmp(b, zero, 15) == 0 && b[15] == 1) return "loopback";
    int mapped = memcmp(b, zero, 10) == 0 && b[10] == 0xff && b[11] == 0xff;
    int compat = memcmp(b, zero, 12) == 0;
    static const uint8_t nat64[12] = {0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0};
    if (mapped || compat || memcmp(b, nat64, 12) == 0) {
        uint32_t a = ((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) | ((uint32_t)b[14] << 8) | b[15];
        const char *w = vet4_(a);
        return *w ? w : (compat ? "reserved" : "");
    }
    if ((b[0] & 0xfe) == 0xfc) return "private";
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return "link-local";
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0) return "private";
    if (b[0] == 0xff) return "multicast";
    if (b[0] == 0x20 && b[1] == 0x02) {
        uint32_t a = ((uint32_t)b[2] << 24) | ((uint32_t)b[3] << 16) | ((uint32_t)b[4] << 8) | b[5];
        return vet4_(a);
    }
    return "";
}
