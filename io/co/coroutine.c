/*
 * SHORT CIRCUIT: COROUTINE -- Single-threaded coroutines.
 *
 * Copyright (c) 2022, Alex O'Brien <3541ax@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Affero General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <ucontext.h>

#include <a3/log.h>
#include <a3/sll.h>
#include <a3/util.h>

#include "coroutine.h"
#include "config.h"

#if !defined(NDEBUG) && defined(SC_HAVE_VALGRIND)
#include <memcheck.h>
#endif

typedef struct ScCoCtx
{
    ucontext_t ctx;
} ScCoCtx;

typedef struct ScCoMain
{
    ScCoCtx ctx;
    A3_SLL(spawn_queue, ScCoroutine) spawn_queue;
    ScEventLoop* ev;
    size_t       count;
} ScCoMain;

typedef struct ScCoDeferred
{
    ScCoDeferredCb f;
    void*          data;
    A3_SLL_LINK(struct ScCoDeferred) link;
} ScCoDeferred;

typedef struct ScCoroutine
{
    uint8_t stack[SC_CO_STACK_SIZE];
    ScCoCtx ctx;
    A3_SLL(deferred, ScCoDeferred) deferred;
    A3_SLL_LINK(ScCoroutine) link;
    ScCoMain* parent;
    ssize_t   value;
#ifndef NDEBUG
    uint32_t vg_stack_id;
#endif
    bool done;
} ScCoroutine;

static A3_THREAD_LOCAL ScCoroutine* CURRENT = NULL;

typedef void (*ScCoTrampoline)(void);

// Standards-compliant ucontext requires that all arguments to the entry point be ints. On platforms
// where sizeof(int) == sizeof(void*), this works fine. Where sizeof(int) < sizeof(void*), annoying
// hackery is necessary to split and recombine pointers to/from ints. Thankfully, non-ancient
// versions of glibc make pointer-sized arguments work on 64-bit platforms.
#if defined(SC_UINT_SIZE_PTR) ||                                                                   \
    (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 8)) &&          \
     defined(SC_X86_64))
#define SC_CO_BEGIN_ARGS(ENTRY, DATA) 2, (uintptr_t)(ENTRY), (uintptr_t)(DATA)

static void sc_co_begin(ScCoEntry entry, void* data) {

#elif defined(SC_UINT_SIZE_HALF_PTR)
#define SC_CO_P_SPLIT(P)              (unsigned int)(uintptr_t)(P), (unsigned int)((uintptr_t)(P) >> 32)
#define SC_CO_BEGIN_ARGS(ENTRY, DATA) 4, SC_CO_P_SPLIT(ENTRY), SC_CO_P_SPLIT(DATA)

static void sc_co_begin(unsigned int entry_l, unsigned int entry_h, unsigned int data_l,
                        unsigned int data_h) {
#define SC_CO_P_COMBINE(L, H)         (void*)((L) | (uintptr_t)(H) << 32);
    ScCoEntry entry = SC_CO_P_COMBINE(entry_l, entry_h);
    void*     data  = SC_CO_P_COMBINE(data_l, data_h);
#undef SC_CO_P_COMBINE

#else
#error "Unsupported pointer size."
#endif

    assert(entry);
    assert(CURRENT);

    CURRENT->value = entry(data);

    A3_SLL_FOR_EACH(ScCoDeferred, deferred, &CURRENT->deferred, link) {
        deferred->f(deferred->data);
    }
    CURRENT->done = true;

    sc_co_yield();

     NOTE: Returning from here will terminate the process.
}

static void sc_co_ctx_init(ScCoroutine* self, void* stack, size_t stack_size, ScCoEntry entry,
                           void* data)
{
    assert(self);
    assert(stack);
    assert(stack_size);
    assert(entry);

    ucontext_t* ctx = &self->ctx.ctx;

    A3_UNWRAPSD(getcontext(ctx));
    ctx->uc_stack = (stack_t) { .ss_sp = stack, .ss_size = stack_size };
    ctx->uc_link  = NULL;
    makecontext(ctx, (ScCoTrampoline)sc_co_begin, SC_CO_BEGIN_ARGS(entry, data));
}

static void sc_co_ctx_swap(ScCoCtx* dst, ScCoCtx* src)
{
    assert(dst);
    assert(src);

    A3_UNWRAPSD(swapcontext(&dst->ctx, &src->ctx));
}

ScCoMain* sc_co_main_new(ScEventLoop* ev)
{
    A3_TRACE("Creating main coroutine context.");

    A3_UNWRAPNI(ScCoMain*, ret, malloc(sizeof(*ret)));
    A3_UNWRAPSD(getcontext(&ret->ctx.ctx));

    ret->ev    = ev;
    ret->count = 0;

    A3_SLL_INIT(&ret->spawn_queue);

    return ret;
}

void sc_co_main_free(ScCoMain* main)
{
    assert(main);
    free(main);
}

ScEventLoop* sc_co_main_event_loop(ScCoMain* main)
{
    assert(main);
    return main->ev;
}

void sc_co_main_pending_resume(ScCoMain* main)
{
    assert(main);
    while (!A3_SLL_IS_EMPTY(&main->spawn_queue)) {
        ScCoroutine* co = A3_SLL_HEAD(&main->spawn_queue);
        A3_SLL_DEQUEUE(&main->spawn_queue, link);
        sc_co_resume(co, 0);
    }
}

/*
size_t sc_co_count(ScCoMain* main)
{
    assert(main);
    return main->count;
}*/

ScCoroutine* sc_co_new(ScCoMain* main, ScCoEntry entry, void* data)
{
    assert(main);
    assert(entry);

    A3_UNWRAPNI(ScCoroutine*, ret, calloc(1, sizeof(*ret)));
    ret->parent = main;
    ret->value  = 0;
    ret->done   = false;
#if !defined(NDEBUG) && defined(SC_HAVE_VALGRIND)
    ret->vg_stack_id = VALGRIND_STACK_REGISTER(ret->stack, ret->stack + sizeof(ret->stack));
#endif

    A3_SLL_INIT(&ret->deferred);
    sc_co_ctx_init(ret, &ret->stack, sizeof(ret->stack), entry, data);

    main->count++;
    return ret;
}

ScCoroutine* sc_co_spawn(ScCoEntry entry, void* data)
{
    assert(CURRENT);
    assert(entry);

    ScCoroutine* ret = sc_co_new(CURRENT->parent, entry, data);
    A3_SLL_ENQUEUE(&CURRENT->parent->spawn_queue, ret, link);

    return ret;
}

ssize_t sc_co_yield()
{
    assert(CURRENT);

    ScCoroutine* self = CURRENT;
    CURRENT           = NULL;

    sc_co_ctx_swap(&self->ctx, &self->parent->ctx);

    assert(CURRENT);
    assert(CURRENT == self);
    return self->value;
}

static void sc_co_free(ScCoroutine* co)
{
    assert(co);

#if !defined(NDEBUG) && defined(SC_HAVE_VALGRIND)
    VALGRIND_STACK_DEREGISTER(co->vg_stack_id);
#endif

    co->parent->count--;
    free(co);
}

ssize_t sc_co_resume(ScCoroutine* co, ssize_t param)
{
    assert(co);
    assert(!CURRENT);

    co->value = param;
    CURRENT   = co;
    sc_co_ctx_swap(&co->parent->ctx, &co->ctx);

    assert(!CURRENT);
    ssize_t ret = co->value;
    if (co->done)
        sc_co_free(co);

    return ret;
}

void sc_co_defer_on(ScCoroutine* co, ScCoDeferredCb f, void* data)
{
    assert(co);
    assert(f);

    A3_UNWRAPNI(ScCoDeferred*, def, calloc(1, sizeof(*def)));
    *def = (ScCoDeferred) {
        .f    = f,
        .data = data,
    };

    A3_SLL_PUSH(&co->deferred, def, link);
}

void sc_co_defer(ScCoDeferredCb f, void* data) { sc_co_defer_on(CURRENT, f, data); }

ScEventLoop* sc_co_event_loop() {
    assert(CURRENT);
    return CURRENT->parent->ev;
}

ScCoroutine* sc_co_current() {
    assert(CURRENT);
    return CURRENT;
}
