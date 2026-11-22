/* naeb's side of a project policy library (docs/naeb/adr/0001): dlopen it,
   check the interface it was built for, and call
   aether_naeb_policy_v1(&NAEB_FENCE_API, ctx). The policy calls back
   through the table; each call is copied into ctx as an op, which nib.fence.
   policy then applies to the Fence in Aether. The policy gets only this
   table and C strings: none of naeb's own layouts cross the boundary.

   The table's layout is the interface (ae/policy_lib/naeb/policy declares
   it field for field). Append only, and bump NAEB_POLICY_INTERFACE with it.
   The library stays loaded for the life of the process: it carries a
   runtime of its own. */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAEB_POLICY_INTERFACE 2

enum {
    NAEB_OP_ALLOW_READ = 1,
    NAEB_OP_DENY_READ,
    NAEB_OP_ALLOW_WRITE,
    NAEB_OP_DENY_WRITE,
    NAEB_OP_ALLOW_HOST,
    NAEB_OP_PASS_ENV,
    NAEB_OP_SET_ENV,
    NAEB_OP_ALLOW_LOOPBACK,
    NAEB_OP_OPEN_HOME,
    NAEB_OP_SETTING
};

struct naeb_op {
    int kind;
    char *a;
    char *b;
    int32_t port;
};

struct naeb_policy_ctx {
    char *home;
    char *project;
    char *platform;
    struct naeb_op *ops;
    int n;
    int cap;
    int bad;   /* a call the policy made with a NULL string */
    char err[1024];
};

struct naeb_fence_api {
    int64_t version;
    void (*allow_read)(void *fence, const char *path);
    void (*deny_read)(void *fence, const char *path);
    void (*allow_write)(void *fence, const char *path);
    void (*deny_write)(void *fence, const char *path);
    void (*allow_host)(void *fence, const char *host, int32_t port);
    void (*pass_env)(void *fence, const char *name);
    void (*set_env)(void *fence, const char *name, const char *value);
    void (*allow_loopback)(void *fence);
    void (*open_home)(void *fence);
    const char *(*home)(void *fence);
    const char *(*project_root)(void *fence);
    const char *(*platform)(void *fence);
    /* version 2: a named setting naeb applies or refuses (unknown names stop
       the policy from loading), e.g. "maven.broker". */
    void (*setting)(void *fence, const char *name, const char *value);
};

static char *dup_(const char *s) { return strdup(s ? s : ""); }

static void push_(void *fence, int kind, const char *a, const char *b, int32_t port, int strings) {
    struct naeb_policy_ctx *c = fence;
    if ((strings >= 1 && a == NULL) || (strings >= 2 && b == NULL)) {
        c->bad = 1;
        return;
    }
    if (c->n == c->cap) {
        int cap = c->cap ? c->cap * 2 : 16;
        struct naeb_op *ops = realloc(c->ops, (size_t)cap * sizeof *ops);
        if (ops == NULL) {
            c->bad = 1;
            return;
        }
        c->ops = ops;
        c->cap = cap;
    }
    struct naeb_op *op = &c->ops[c->n++];
    op->kind = kind;
    op->a = dup_(a);
    op->b = dup_(b);
    op->port = port;
}

static void allow_read_(void *f, const char *p) { push_(f, NAEB_OP_ALLOW_READ, p, NULL, 0, 1); }
static void deny_read_(void *f, const char *p) { push_(f, NAEB_OP_DENY_READ, p, NULL, 0, 1); }
static void allow_write_(void *f, const char *p) { push_(f, NAEB_OP_ALLOW_WRITE, p, NULL, 0, 1); }
static void deny_write_(void *f, const char *p) { push_(f, NAEB_OP_DENY_WRITE, p, NULL, 0, 1); }
static void allow_host_(void *f, const char *h, int32_t port) { push_(f, NAEB_OP_ALLOW_HOST, h, NULL, port, 1); }
static void pass_env_(void *f, const char *n) { push_(f, NAEB_OP_PASS_ENV, n, NULL, 0, 1); }
static void set_env_(void *f, const char *n, const char *v) { push_(f, NAEB_OP_SET_ENV, n, v, 0, 2); }
static void allow_loopback_(void *f) { push_(f, NAEB_OP_ALLOW_LOOPBACK, NULL, NULL, 0, 0); }
static void open_home_(void *f) { push_(f, NAEB_OP_OPEN_HOME, NULL, NULL, 0, 0); }
static void setting_(void *f, const char *n, const char *v) { push_(f, NAEB_OP_SETTING, n, v, 0, 2); }
static const char *home_(void *f) { return ((struct naeb_policy_ctx *)f)->home; }
static const char *project_root_(void *f) { return ((struct naeb_policy_ctx *)f)->project; }
static const char *platform_(void *f) { return ((struct naeb_policy_ctx *)f)->platform; }

static const struct naeb_fence_api NAEB_FENCE_API = {
    NAEB_POLICY_INTERFACE,
    allow_read_, deny_read_, allow_write_, deny_write_, allow_host_,
    pass_env_, set_env_, allow_loopback_, open_home_,
    home_, project_root_, platform_,
    setting_,
};

int naeb_policy_interface(void) { return NAEB_POLICY_INTERFACE; }

void *naeb_policy_new(const char *home, const char *project, const char *platform) {
    struct naeb_policy_ctx *c = calloc(1, sizeof *c);
    if (c == NULL) return NULL;
    c->home = dup_(home);
    c->project = dup_(project);
    c->platform = dup_(platform);
    return c;
}

/* 0: the policy ran. Otherwise naeb_policy_error says why: 1 the library
   would not load, 2 it is no naeb policy, 3 it was built for another
   interface, 4 the policy refused the table or passed a NULL string. */
int naeb_policy_load(void *ctx, const char *path) {
    struct naeb_policy_ctx *c = ctx;
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        const char *e = dlerror();
        snprintf(c->err, sizeof c->err, "cannot load %s: %s", path, e ? e : "unknown error");
        return 1;
    }
    int32_t (*iface)(void) = (int32_t (*)(void))dlsym(h, "aether_naeb_policy_interface");
    int32_t (*entry)(const struct naeb_fence_api *, void *) =
        (int32_t (*)(const struct naeb_fence_api *, void *))dlsym(h, "aether_naeb_policy_v1");
    if (iface == NULL || entry == NULL) {
        snprintf(c->err, sizeof c->err, "%s is not a naeb policy library", path);
        return 2;
    }
    int32_t got = iface();
    if (got != NAEB_POLICY_INTERFACE) {
        snprintf(c->err, sizeof c->err, "the policy library was built for interface %d, this naeb speaks %d", (int)got, NAEB_POLICY_INTERFACE);
        return 3;
    }
    if (entry(&NAEB_FENCE_API, c) != 0 || c->bad) {
        snprintf(c->err, sizeof c->err, "the policy library %s refused naeb's interface or passed a null string", path);
        return 4;
    }
    return 0;
}

const char *naeb_policy_error(void *ctx) { return ((struct naeb_policy_ctx *)ctx)->err; }
int naeb_policy_op_count(void *ctx) { return ((struct naeb_policy_ctx *)ctx)->n; }
int naeb_policy_op_kind(void *ctx, int i) { return ((struct naeb_policy_ctx *)ctx)->ops[i].kind; }
const char *naeb_policy_op_a(void *ctx, int i) { return ((struct naeb_policy_ctx *)ctx)->ops[i].a; }
const char *naeb_policy_op_b(void *ctx, int i) { return ((struct naeb_policy_ctx *)ctx)->ops[i].b; }
int naeb_policy_op_port(void *ctx, int i) { return ((struct naeb_policy_ctx *)ctx)->ops[i].port; }

void naeb_policy_free(void *ctx) {
    struct naeb_policy_ctx *c = ctx;
    if (c == NULL) return;
    for (int i = 0; i < c->n; i++) {
        free(c->ops[i].a);
        free(c->ops[i].b);
    }
    free(c->ops);
    free(c->home);
    free(c->project);
    free(c->platform);
    free(c);
}
