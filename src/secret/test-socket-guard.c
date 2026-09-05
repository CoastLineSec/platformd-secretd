/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int bind_socket(const char *path, int type) {
        struct sockaddr_un address = { .sun_family = AF_UNIX };
        int fd, r;

        if (strlen(path) >= sizeof address.sun_path)
                return -ENAMETOOLONG;
        strcpy(address.sun_path, path);
        fd = socket(AF_UNIX, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;
        if (bind(fd, (struct sockaddr*) &address, sizeof address) < 0 ||
            (type == SOCK_STREAM && listen(fd, 16) < 0)) {
                r = -errno;
                close(fd);
                return r;
        }
        return fd;
}

static int set_path(const char *name, const char *prefix, const char *path) {
        char value[PATH_MAX];
        int n;

        n = snprintf(value, sizeof value, "%s%s", prefix, path);
        if (n < 0 || (size_t) n >= sizeof value)
                return -ENAMETOOLONG;
        return setenv(name, value, 1) < 0 ? -errno : 0;
}

int main(int argc, char *argv[]) {
        static const char *const path_variables[] = {
                "TMPDIR", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME", "XDG_STATE_HOME", "RUNTIME_DIRECTORY", "STATE_DIRECTORY",
                "CACHE_DIRECTORY", "LOGS_DIRECTORY", "CONFIGURATION_DIRECTORY",
                "CREDENTIALS_DIRECTORY", "ENCRYPTED_CREDENTIALS_DIRECTORY",
                "PLATFORMD_TRUSTD_RUNTIME", "PLATFORMD_TRUSTD_STATE", "PLATFORMD_VERIFYD_RUNTIME",
        };
        static const char *const socket_variables[] = {
                "PLATFORMD_TRUST_SOCKET", "PLATFORMD_VERIFY_SOCKET", "PLATFORMD_ASK_PASSWORD_SOCKET",
                "SECRETD_VAULT_KEY_FILE", "PLATFORMD_VERIFY_PAM_CONFDIR",
        };
        char *root = NULL;
        char directory[PATH_MAX], administrative[PATH_MAX], backend[PATH_MAX], notification[PATH_MAX];
        struct stat before, after;
        struct pollfd sockets[3] = { { .fd = -1 }, { .fd = -1 }, { .fd = -1 } };
        bool created = false;
        pid_t pid = -1;
        int r = EXIT_FAILURE, status;

        if (argc < 2)
                return EXIT_FAILURE;
        if (asprintf(&root, "%s/platformd-sentinel.XXXXXX", getenv("TMPDIR") ?: "/tmp") < 0)
                return EXIT_FAILURE;
        if (!mkdtemp(root)) {
                free(root);
                return EXIT_FAILURE;
        }
        snprintf(directory, sizeof directory, "%s/platformd-secretd", root);
        snprintf(administrative, sizeof administrative, "%s/platformd-secretd/io.platformd.Secret", root);
        snprintf(backend, sizeof backend, "%s/backend", root);
        snprintf(notification, sizeof notification, "%s/notify", root);
        if (mkdir(directory, 0700) < 0)
                goto finish;
        created = true;
        sockets[0].fd = bind_socket(administrative, SOCK_STREAM);
        sockets[1].fd = bind_socket(backend, SOCK_STREAM);
        sockets[2].fd = bind_socket(notification, SOCK_DGRAM);
        for (size_t i = 0; i < 3; i++) {
                if (sockets[i].fd < 0)
                        goto finish;
                sockets[i].events = POLLIN;
        }
        if (lstat(administrative, &before) < 0)
                goto finish;

        pid = fork();
        if (pid < 0)
                goto finish;
        if (pid == 0) {
                for (size_t i = 0; i < sizeof path_variables / sizeof path_variables[0]; i++)
                        if (set_path(path_variables[i], "", root) < 0)
                                _exit(EXIT_FAILURE);
                for (size_t i = 0; i < sizeof socket_variables / sizeof socket_variables[0]; i++)
                        if (set_path(socket_variables[i], "", backend) < 0)
                                _exit(EXIT_FAILURE);
                if (set_path("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=", backend) < 0 ||
                    set_path("DBUS_SESSION_BUS_ADDRESS", "unix:path=", backend) < 0 ||
                    set_path("NOTIFY_SOCKET", "", notification) < 0 ||
                    set_path("TSS2_TCTI", "device:", backend) < 0 ||
                    setenv("PLATFORMD_TEST_INNER", "1", 1) < 0 ||
                    setenv("SECRETD_TEST_SESSION_ID", "inherited-session", 1) < 0 ||
                    setenv("XDG_SESSION_ID", "inherited-session", 1) < 0 ||
                    setenv("LISTEN_FDS", "1", 1) < 0 ||
                    setenv("LISTEN_PID", "1", 1) < 0 ||
                    setenv("LISTEN_FDNAMES", "inherited", 1) < 0 ||
                    setenv("WATCHDOG_USEC", "1", 1) < 0)
                        _exit(EXIT_FAILURE);
                execvp(argv[1], argv + 1);
                _exit(EXIT_FAILURE);
        }
        while (waitpid(pid, &status, 0) < 0)
                if (errno != EINTR)
                        goto finish;
        pid = -1;
        if (lstat(administrative, &after) < 0 ||
            before.st_dev != after.st_dev || before.st_ino != after.st_ino || !S_ISSOCK(after.st_mode)) {
                fprintf(stderr, "Inherited administrative socket was replaced.\n");
                goto finish;
        }
        if (poll(sockets, 3, 0) != 0) {
                fprintf(stderr, "Inherited service endpoint received traffic.\n");
                goto finish;
        }
        if (WIFEXITED(status))
                r = WEXITSTATUS(status);
finish:
        if (pid > 0) {
                (void) kill(pid, SIGTERM);
                (void) waitpid(pid, NULL, 0);
        }
        for (size_t i = 0; i < 3; i++)
                if (sockets[i].fd >= 0)
                        close(sockets[i].fd);
        (void) unlink(administrative);
        (void) unlink(backend);
        (void) unlink(notification);
        if (created)
                (void) rmdir(directory);
        (void) rmdir(root);
        free(root);
        return r;
}
