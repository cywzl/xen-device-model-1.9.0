#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>

#include "mock.h"

typedef struct value {
    const void *value;
    struct value *next;
} value_t;

typedef struct func {
    const char *name;
    struct func *next, *prev;
    struct value *first, *last;
} func_t;

static func_t *funcs;

#undef fail_if
static void fail_if(int cond, const char *s, const char *fn, int ln)
{
    if (!cond) return;
    fprintf(stderr, "%s:%d: failed condition %s\n", fn, ln, s);
    _exit(1);
}
#define fail_if(cond) fail_if(cond, #cond, fn, ln)

static func_t*
get_func(const char *name, int create, const char *fn, int ln)
{
    func_t *f;
    for (f = funcs; f; f = f->next)
        if (strcmp(f->name, name) == 0)
            return f;
    fail_if(!create);
    f = (func_t *) calloc(1, sizeof(*f));
    fail_if(!f);
    f->name = name;
    if (funcs) funcs->prev = f;
    f->next = funcs;
    funcs = f;
    return f;
}

void _with_return(const char *name, const void *ret, const char *fn, int ln)
{
    func_t *f = get_func(name, 1, fn, ln);
    value_t *v = (value_t *) calloc(1, sizeof(*v));
    fail_if(v == NULL);
    v->value = ret;
    if (!f->first) f->first = v;
    if (f->last) f->last->next = v;
    f->last = v;
}

const void *_mock(const char *name, const char *fn, int ln)
{
    func_t *f = get_func(name, 0, fn, ln);
    value_t *v = f->first;
    fail_if(v == NULL);
    const void *ret = v->value;
    f->first = v->next;
    if (f->last == v) {
        if (f->prev) f->prev->next = f->next;
        if (f->next) f->next->prev = f->prev;
        if (funcs == f) funcs = f->next;
        free(f);
    }
    free(v);
    return ret;
}

int mock_check_left(void)
{
    int found = 0;
    func_t *f;
    value_t *v;

    for (f = funcs; f; f = f->next)
        for (v = f->first; v; v = v->next) {
            found = 1;
            fprintf(stderr, "Value %p still present for %s\n", v->value, f->name);
        }

    return !found;
}

