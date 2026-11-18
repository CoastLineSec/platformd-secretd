/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <systemd/sd-login.h>
#include <systemd/sd-bus.h>

int __real_sd_bus_request_name(sd_bus *bus, const char *name, uint64_t flags);

int __wrap_sd_bus_request_name(sd_bus *bus, const char *name, uint64_t flags) {
        int r = __real_sd_bus_request_name(bus, name, flags);

        if (r >= 0 && strcmp(name, "org.freedesktop.secrets") == 0)
                r = __real_sd_bus_request_name(bus, "org.freedesktop.login1", 0);
        return r;
}

int __wrap_sd_uid_get_sessions(uid_t uid, int require_active, char ***ret) {
        const char *path = getenv("SECRETD_TEST_LOGIN_FILE");
        char value[64], **sessions;
        FILE *file;

        if (!path)
                return -ENODATA;
        file = fopen(path, "re");
        if (!file)
                return -errno;
        if (!fgets(value, sizeof value, file)) {
                fclose(file);
                return -EIO;
        }
        fclose(file);
        value[strcspn(value, "\n")] = 0;
        if (strcmp(value, "error") == 0)
                return -EIO;
        sessions = calloc(2, sizeof(char *));
        if (!sessions)
                return -ENOMEM;
        if (*value) {
                sessions[0] = strdup(value);
                if (!sessions[0]) {
                        free(sessions);
                        return -ENOMEM;
                }
        }
        *ret = sessions;
        return !!*value;
}

int __wrap_sd_session_get_uid(const char *session, uid_t *ret) {
        *ret = getuid();
        return 0;
}

int __wrap_sd_session_get_class(const char *session, char **ret) {
        *ret = strdup(strcmp(session, "manager") == 0 ? "manager" : "user");
        return *ret ? 0 : -ENOMEM;
}

int __wrap_sd_session_get_state(const char *session, char **ret) {
        *ret = strdup(strcmp(session, "closing") == 0 ? "closing" : "active");
        return *ret ? 0 : -ENOMEM;
}
