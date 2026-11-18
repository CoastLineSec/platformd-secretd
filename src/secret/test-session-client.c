/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>
#include <libsecret/secret.h>

int main(int argc, char **argv) {
        GError *error = NULL;
        gchar *value = NULL;
        gboolean ok;

        if (argc != 4)
                return EXIT_FAILURE;
        if (strcmp(argv[1], "store") == 0)
                ok = secret_password_store_sync(SECRET_SCHEMA_COMPAT_NETWORK, argv[2], "volatile-label",
                                                 "synthetic-session-secret", NULL, &error,
                                                 "user", "platformd-test", "server", argv[3],
                                                 "protocol", "smb", NULL);
        else if (strcmp(argv[1], "clear") == 0)
                ok = secret_password_clear_sync(SECRET_SCHEMA_COMPAT_NETWORK, NULL, &error,
                                                 "user", "platformd-test", "server", argv[3],
                                                 "protocol", "smb", NULL);
        else {
                value = secret_password_lookup_sync(SECRET_SCHEMA_COMPAT_NETWORK, NULL, &error,
                                                     "user", "platformd-test", "server", argv[3],
                                                     "protocol", "smb", NULL);
                ok = strcmp(argv[1], "missing") == 0 ? value == NULL :
                        value && strcmp(value, "synthetic-session-secret") == 0;
        }
        secret_password_free(value);
        if (error) {
                g_printerr("%s\n", error->message);
                g_error_free(error);
                return EXIT_FAILURE;
        }
        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
