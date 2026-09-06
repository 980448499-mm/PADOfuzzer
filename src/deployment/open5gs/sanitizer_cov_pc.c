/*
 * LLVM SanitizerCoverage — trace-pc mode.
 * Compile: clang -shared -fPIC -o libsanitizer_cov_pc.so sanitizer_cov_pc.c
 * Usage:   LD_PRELOAD=./libsanitizer_cov_pc.so <binary>
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

/* Simple linear PC buffer — coverage = set of executed PCs */
#define MAX_PCS (1 << 20)  /* 1M entries, 8 MB */
static uintptr_t *pc_buffer = NULL;
static volatile uint32_t pc_index = 0;
static int pc_shm_fd = -1;
static char pc_shm_path[128];

__attribute__((constructor))
static void pc_cov_init(void)
{
    snprintf(pc_shm_path, sizeof(pc_shm_path),
             "/open5gs_cov_pc_%d", getpid());

    pc_shm_fd = shm_open(pc_shm_path, O_CREAT | O_RDWR, 0644);
    if (pc_shm_fd < 0) {
        pc_buffer = mmap(NULL, MAX_PCS * sizeof(uintptr_t),
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return;
    }
    size_t sz = MAX_PCS * sizeof(uintptr_t) + sizeof(uint32_t);
    if (ftruncate(pc_shm_fd, sz) < 0) { close(pc_shm_fd); return; }
    pc_buffer = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                     MAP_SHARED, pc_shm_fd, 0);
    if (pc_buffer == MAP_FAILED) { close(pc_shm_fd); return; }

    fprintf(stderr, "[libsanitizer_cov_pc] init pid=%d shm=%s buffer=%p\n",
            getpid(), pc_shm_path, (void*)pc_buffer);
}

__attribute__((destructor))
static void pc_cov_fini(void)
{
    /* Write final count at the end of the buffer */
    if (pc_buffer && pc_buffer != MAP_FAILED) {
        uint32_t *count = (uint32_t*)(pc_buffer + MAX_PCS);
        *count = pc_index;
    }
    if (pc_shm_fd >= 0) { close(pc_shm_fd); shm_unlink(pc_shm_path); }
    fprintf(stderr, "[libsanitizer_cov_pc] cleanup pid=%d pc_count=%u\n",
            getpid(), pc_index);
}

/* Called on every edge. Store PC for later hashing. */
void __sanitizer_cov_trace_pc(void)
{
    uint32_t idx = __sync_fetch_and_add(&pc_index, 1);
    if (idx < MAX_PCS && pc_buffer)
        pc_buffer[idx] = (uintptr_t)__builtin_return_address(0);
}
