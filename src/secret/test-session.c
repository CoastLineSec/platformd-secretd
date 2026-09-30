/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/types.h>

int __wrap_sd_uid_get_display(uid_t uid, char **ret) {
        return -ENODATA;
}
