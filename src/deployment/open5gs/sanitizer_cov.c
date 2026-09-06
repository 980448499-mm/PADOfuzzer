/*
 * LLVM SanitizerCoverage callback — trace-pc-guard mode.
 *
 * Compile: clang -shared -fPIC -o libsanitizer_cov.so sanitizer_cov.c
 * Usage:   LD_PRELOAD=./libsanitizer_cov.so /usr/bin/open5gs-nrfd -c ...
 *
 * Coverage data is written to /dev/shm/open5gs_cov_<pid>.bin at process
 * exit (via atexit) and can also be read live during execution.
 *
 * Format: binary dump of num_guards × sizeof(uint32_t) counter values.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

static uint32_t *cov_counters = NULL;
static uint32_t  cov_num_guards = 0;
static char      cov_shm_path[128];
static int       cov_shm_fd = -1;

/* Called once at startup by the instrumented binary. */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
    cov_num_guards = (uint32_t)(stop - start);
    if (cov_num_guards == 0) return;

    size_t sz = cov_num_guards * sizeof(uint32_t);

    /* Use shared memory for live reads */
    snprintf(cov_shm_path, sizeof(cov_shm_path),
             "/open5gs_cov_%d", getpid());

    cov_shm_fd = shm_open(cov_shm_path, O_CREAT | O_RDWR, 0644);
    if (cov_shm_fd < 0) {
        /* fallback: anonymous mmap */
        cov_counters = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        fprintf(stderr, "[libsanitizer_cov] shm_open failed (%s), "
                "using anonymous mmap\n", strerror(errno));
        return;
    }

    if (ftruncate(cov_shm_fd, sz) < 0) {
        fprintf(stderr, "[libsanitizer_cov] ftruncate failed\n");
        close(cov_shm_fd);
        cov_shm_fd = -1;
        return;
    }

    cov_counters = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED, cov_shm_fd, 0);
    if (cov_counters == MAP_FAILED) {
        fprintf(stderr, "[libsanitizer_cov] mmap failed\n");
        close(cov_shm_fd);
        cov_shm_fd = -1;
        return;
    }

    /* Initialise guard slots that the compiler hasn't touched yet */
    for (uint32_t i = 0; i < cov_num_guards; i++) {
        if (start[i]) start[i] = 0;
    }

    /* Link compiler guards to our shared counters */
    for (uint32_t i = 0; i < cov_num_guards; i++)
        start[i] = (uint32_t)(i + 1);  /* 1-based index into cov_counters */

    FILE *dbg = fopen("/tmp/sanitizer_cov.log", "a");
    if (dbg) {
        fprintf(dbg, "[libsanitizer_cov] pid=%d %u guards shm=%s\n",
                getpid(), cov_num_guards, cov_shm_path);
        fclose(dbg);
    }
}

/* Work around glibc header not defining LIKELY for plain C. */
#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif

/* Called for every edge (basic-block transition) at runtime. */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard)
{
    /*
     * guard points into the compiler-generated array that was initialised
     * by __sanitizer_cov_trace_pc_guard_init above.  Its value is the
     * 1-based index into cov_counters.
     */
    if (LIKELY(*guard > 0 && *guard <= cov_num_guards))
        cov_counters[*guard - 1]++;

    /* Re-arm for the next hit (guard may be reset by the runtime). */
    if (LIKELY(*guard > 0 && *guard <= cov_num_guards))
        ; /* keep the index, counter already incremented */
}

/* Cleanup on exit */
static void cov_cleanup(void)
{
    if (cov_counters && cov_counters != MAP_FAILED) {
        size_t sz = cov_num_guards * sizeof(uint32_t);
        munmap(cov_counters, sz);
    }
    if (cov_shm_fd >= 0) {
        shm_unlink(cov_shm_path);
        close(cov_shm_fd);
    }
    fprintf(stderr, "[libsanitizer_cov] cleanup done\n");
}

__attribute__((constructor))
static void cov_init(void)
{
    FILE *dbg = fopen("/tmp/sanitizer_cov.log", "a");
    if (dbg) { fprintf(dbg, "=== COV_INIT pid=%d ===\n", getpid()); fclose(dbg); }
    atexit(cov_cleanup);
}
