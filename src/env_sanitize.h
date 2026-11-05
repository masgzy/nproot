/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ENV_SANITIZE_H
#define ENV_SANITIZE_H

#include <stdbool.h>

/**
 * Keep the host environment (Termux PATH, LD_PRELOAD, LD_LIBRARY_PATH,
 * TMPDIR, the glibc rseq probe) from leaking into the guest.  Call it
 * once per guest launch, after the configuration is parsed and before
 * anything of the guest is started.  It is a no-op for sessions
 * without a rootfs of their own; NPROOT_KEEP_ENV=1 disables it.
 *
 * @separate_rootfs: whether this session runs against its own rootfs
 * (as opposed to the default root of "/", where the host IS the
 * guest).
 */
extern void sanitize_guest_environment(bool separate_rootfs);

#endif /* ENV_SANITIZE_H */
