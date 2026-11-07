/* Host regression test for the EFAULT-safe shield scan (`make check-shield`).
 *
 * Recreates the device musl crash in miniature: an executable
 * file-backed mapping whose length covers pages the backing file does
 * not have (a short or mutated rootfs image).  Reading those pages
 * live = SIGBUS BUS_ADRERR si_code=2 -- byte-for-byte the fatal line
 * the device printed ("signal 7, exit 135"); the old direct scan died
 * on its very first such page.  process_vm_readv reports EFAULT for
 * the same pages instead of faulting, so the snapshot skips them.
 *
 * Includes the shim source directly so the static shield functions
 * are callable.  Runs on any Linux host (x86_64 and aarch64).
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "preload/nproot_preload.c"

#define MAP_LEN   0x10000UL     /* 64 KiB mapping */
#define FILE_LEN  0x8000UL      /* backing file: only 32 KiB */
#define NR_TEST   435

int main(void)
{
        const char *path = "/tmp/nproot-shield-test.bin";
        unsigned char stub[7] = { 0xB8, (NR_TEST & 0xFF),
                                  (NR_TEST >> 8) & 0xFF, 0x00, 0x00,
                                  0x0F, 0x05 };
        unsigned char *map, *snap;
        uintptr_t start;
        size_t off;
        int fd, skipped = 0, hits, expect_hits, rc = 0;
        int nrs[1] = { NR_TEST };

        fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
                perror("open");
                return 1;
        }
        for (off = 0x100; off + sizeof(stub) <= FILE_LEN; off += 0x100)
                pwrite(fd, stub, sizeof(stub), (off_t)off);
        if (ftruncate(fd, FILE_LEN) != 0) {
                perror("ftruncate");
                return 1;
        }
        close(fd);

        /* The mapping lies: [0, MAP_LEN) from a FILE_LEN file. */
        map = mmap(NULL, MAP_LEN, PROT_READ | PROT_EXEC, MAP_PRIVATE,
                   open(path, O_RDONLY), 0);
        if (map == MAP_FAILED) {
                perror("mmap");
                return 1;
        }
        start = (uintptr_t)map;

        /* Proof the legacy direct scan dies: a child reads past EOF. */
        {
                pid_t pid = fork();

                if (pid == 0) {
                        volatile unsigned char b;

                        b = map[FILE_LEN + 64];
                        (void)b;
                        _exit(0);
                }
                {
                        int st;

                        waitpid(pid, &st, 0);
                        printf("direct read child: %s (status %d)\n",
                               WIFSIGNALED(st) ? "KILLED BY SIGNAL" :
                                                 "survived",
                               st);
                }
        }

        shield_mark(nrs, 1);
        if (!shield_pvmr_usable()) {
                printf("FAIL: process_vm_readv unusable on this host\n");
                return 1;
        }
        if (shield_snapshot_range(start, start + MAP_LEN, &snap,
                                  &skipped) != 0) {
                printf("FAIL: snapshot returned -1\n");
                return 1;
        }
        hits = shield_scan_range(start, start + MAP_LEN, snap);
        expect_hits = (int)((FILE_LEN - 0x100) / 0x100);

        printf("hits=%d (expect %d) skipped_pages=%d (expect %d)\n",
               hits, expect_hits, skipped,
               (int)((MAP_LEN - FILE_LEN) / 0x1000));

        if (hits != expect_hits)
                rc = 2;
        if (skipped != (int)((MAP_LEN - FILE_LEN) / 0x1000))
                rc = 3;

        /* Apply the queued patches and verify they landed on the GUEST
         * mapping (regression guard: collecting snapshot-buffer
         * addresses instead of guest addresses once made every patch
         * target a munmapped buffer -- "hardened 0" on x86_64). */
        if (mprotect(map, MAP_LEN, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                printf("NOTE: mprotect RWX refused; skipping the apply "
                       "check (rc so far %d)\n", rc);
                munmap(snap, MAP_LEN);
                if (rc == 0)
                        printf("PASS (scan only): bad pages skipped, "
                               "readable stubs found\n");
                else
                        printf("FAIL rc=%d\n", rc);
                return rc;
        }
        {
                int applied = shield_apply_patches();
                static const unsigned char rep[7] =
                        { 0xB8, 0xDA, 0xFF, 0xFF, 0xFF, 0x90, 0x90 };

                munmap(snap, MAP_LEN);
                printf("applied=%d (expect %d)\n", applied, expect_hits);
                if (applied != expect_hits) {
                        rc = 4;
                } else if (memcmp(map + 0x100, rep, sizeof(rep)) != 0) {
                        printf("FAIL: guest stub at +0x100 not patched\n");
                        rc = 5;
                }
                /* A patch queued against a 0xFF-filled snapshot page
                 * would have memcpy'd into the beyond-EOF mapping and
                 * SIGBUSed the test right here -- reaching this line
                 * with applied == expect_hits is the proof. */
        }
        if (rc == 0)
                printf("PASS: bad pages skipped, readable stubs found "
                       "and patched in place\n");
        else
                printf("FAIL rc=%d\n", rc);
        return rc;
}
