#include <stdlib.h>
#include <stdio.h>
#include "allocHandler.h"
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <string.h>
#include "tree.h"
#include "queue.h"

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))
static void mleakdetect_atexit(void);
/**
 * 
*/
#define offsetof(type, member) ((size_t) &((type *)0)->member)

#define container_of(ptr, type, member) ({                      \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);         \
    (type *)( (char *)__mptr - offsetof(type, member) ); })


struct memchunk {
  size_t size;
  void *caller;
  int count;
  RB_ENTRY(memchunk) tree;
  TAILQ_ENTRY(memchunk) next;
  unsigned char data[0];
};

/**
 * dynamic call interfaces to memory allocation functions in libc.so
 */
void* (*lt_malloc)(size_t size);
void  (*lt_free)(void* ptr);
void* (*lt_realloc)(void *ptr, size_t size);
void* (*lt_calloc)(size_t nmemb, size_t size);

// glibc/eglibc: dlsym uses calloc internally now, so use weak symbol to get their symbol
extern "C" void* __libc_malloc(size_t size) __attribute__((weak));
extern "C" void  __libc_free(void* ptr) __attribute__((weak));
extern "C" void* __libc_realloc(void *ptr, size_t size) __attribute__((weak));
extern "C" void* __libc_calloc(size_t nmemb, size_t size) __attribute__((weak));

/*
 * underlying allocation, de-allocation used within
 * this tool
 */
#define LT_MALLOC  (*lt_malloc)
#define LT_FREE    (*lt_free)
#define LT_REALLOC (*lt_realloc)
#define LT_CALLOC  (*lt_calloc)

static int memchunk_cmp(struct memchunk *, struct memchunk *);

RB_HEAD(memchunk_tree, memchunk);
TAILQ_HEAD(memchunk_list, memchunk);


static int mleakdetect_initialized = 0;
static int mleakdetect_malloc_count = 0;
static int mleakdetect_free_count = 0;
static int mleakdetect_unknown_free_count = 0;

struct memchunk_tree mleakdetect_memchunk;
struct memchunk_list mleakdetect_stat;
struct memchunk_list mleakdetect_unknown_free;

RB_GENERATE(memchunk_tree, memchunk, tree, memchunk_cmp);

typedef struct {
  const char *symbname;
  void *libcsymbol;
  void **localredirect;
} libc_alloc_func_t;

static libc_alloc_func_t libc_alloc_funcs[] = {
  { "calloc", (void*)__libc_calloc, (void**)(&lt_calloc) },
  { "malloc", (void*)__libc_malloc, (void**)(&lt_malloc) },
  { "realloc", (void*)__libc_realloc, (void**)(&lt_realloc) },
  { "free", (void*)__libc_free, (void**)(&lt_free) }
};



static void mem_chunk_initialize(void) {

  RB_INIT(&mleakdetect_memchunk);
  TAILQ_INIT(&mleakdetect_stat);
  TAILQ_INIT(&mleakdetect_unknown_free);

  atexit(mleakdetect_atexit);
}

void init_alloc_wrapper()
{
  libc_alloc_func_t *curfunc;
  unsigned i;

  for (i=0; i<(sizeof(libc_alloc_funcs)/sizeof(libc_alloc_funcs[0])); ++i) {
    curfunc = &libc_alloc_funcs[i];
    if (!*curfunc->localredirect) {
      if (curfunc->libcsymbol) {
        *curfunc->localredirect = curfunc->libcsymbol;
      } else {
        *curfunc->localredirect = dlsym(RTLD_NEXT, curfunc->symbname);
      }
    }
  }
  mem_chunk_initialize();
  mleakdetect_initialized = 1;
}

/** -- libc memory operators wrapper -- **/

static void *malloc0(size_t size, void *caller) {
  struct memchunk *m;

  if (mleakdetect_initialized == 0)
    init_alloc_wrapper();

  m = (struct memchunk *)LT_MALLOC(offsetof(struct memchunk, data[size]));
  if (m == NULL)
    return (NULL);

  m->size = size;
  m->caller = caller;

  mleakdetect_malloc_count++;
  RB_INSERT(memchunk_tree, &mleakdetect_memchunk, m);

  return (m->data);
}

void free0(void *mem, size_t size, void *caller) {
  struct memchunk *m, *m0;

  if (mem == NULL)
    return;
  m0 = (struct memchunk *)((char*)mem - offsetof(struct memchunk, data));

  m = RB_FIND(memchunk_tree, &mleakdetect_memchunk, m0);
  if (m != NULL) {
    RB_REMOVE(memchunk_tree, &mleakdetect_memchunk, m);
    mleakdetect_free_count++;
  } else
    mleakdetect_unknown_free_count++;

  if (m != NULL)
    LT_FREE(m);
  else {
    TAILQ_FOREACH(m0, &mleakdetect_unknown_free, next) {
      if (m0->caller == caller)
        break;
    }
    if (m0 == NULL) {
      m0 = (struct memchunk *)LT_MALLOC(sizeof(*m0));
      memset(m0, 0, sizeof(*m0));
      m0->caller = caller;
      TAILQ_INSERT_TAIL(&mleakdetect_unknown_free, m0, next);
    }
    m0->count++;

    LT_FREE(mem);
  }
}

void *realloc0(void *ptr, size_t size, void *caller) {
  void *r;
  struct memchunk *m, *m0;

  if (mleakdetect_initialized == 0)
    init_alloc_wrapper();

  if (ptr == NULL)
    return malloc0(size, caller);

  m0 = (struct memchunk *)((char*)ptr - offsetof(struct memchunk, data));

  m = RB_FIND(memchunk_tree, &mleakdetect_memchunk, m0);

  if (m == NULL)
    return (LT_REALLOC(ptr, size));

  r = malloc0(size, caller);
  if (r == NULL)
    return (r);
  if (m != NULL) {
    memcpy(r, m->data, MINIMUM(m->size, size));
    free0(m->data, 0, caller);
  }

  return (r);
}

/** -- libc memory operators -- **/

/* malloc
 * in some malloc implementation, there is a recursive call to malloc
 * (for instance, in uClibc 0.9.29 malloc-standard )
 * we use a InternalMonitoringDisablerThreadUp that use a tls variable to prevent several registration
 * during the same malloc
 */
void* operator new(size_t size) {
	return (malloc0(size, __builtin_return_address(0)));
}


void* operator new[] (size_t size) {
	return (malloc0(size, __builtin_return_address(0)));
}


void operator delete (void *p) {
	return (free0(p, 0, __builtin_return_address(0)));
}


void operator delete[] (void *p) {
	return (free0(p, 0, __builtin_return_address(0)));
}
void *malloc(size_t size)
{
	return (malloc0(size, __builtin_return_address(0)));
}

void free(void* p)
{
	return (free0(p, 0, __builtin_return_address(0)));
}

void* realloc(void *p, size_t size)
{
	p = LT_REALLOC(p, size);

	return p;
}

void* calloc(size_t nmemb, size_t size)
{
	void *p;
	p = LT_CALLOC(nmemb, size);

	return p;
}


/**
 * 
*/
int memchunk_cmp(struct memchunk *a, struct memchunk *b) {
  /* (a - b) might > INT_MAX or < INT_MIN.  actually true on OpenBSD. */
  if (a > b)
    return (1);
  else if (a == b)
    return (0);
  return (-1);
}


void printSymbolInfo(const void* address) {
    Dl_info info;
    if (dladdr(address, &info)) {
        printf("Executable or Shared Object: %s\n", info.dli_fname);
        printf("Symbol's Address: %p\n", info.dli_saddr);
        printf("Symbol's Name: %s\n", info.dli_sname);
        printf("Symbol's Base Address: %p\n", info.dli_fbase);
    } else {
        printf("dladdr failed: %s\n", dlerror());
    }
}
void mleakdetect_atexit(void) 
{
	struct memchunk *m;
	  RB_FOREACH(m,	memchunk_tree, &mleakdetect_memchunk)	{
			  printf("%5ld - %p\n", m->size, m->caller);
        printSymbolInfo(m->caller);
		  }
}
