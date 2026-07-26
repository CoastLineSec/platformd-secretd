/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-bus.h>

#define SECRETS_NAME "org.freedesktop.secrets"
#define SECRETS_PATH "/org/freedesktop/secrets"
#define COLLECTION_PATH "/org/freedesktop/secrets/collection/default"

static int new_method(sd_bus *bus, sd_bus_message **ret, const char *path,
                      const char *interface, const char *member) {
        return sd_bus_message_new_method_call(bus, ret, SECRETS_NAME, path, interface, member);
}

static int call(sd_bus *bus, sd_bus_message *request, sd_bus_error *error,
                sd_bus_message **reply) {
        return sd_bus_call(bus, request, 5 * 1000 * 1000, error, reply);
}

static int open_plain_session(sd_bus *bus, char **ret) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *request = NULL, *reply = NULL;
        const char *path;
        int r;

        r = new_method(bus, &request, SECRETS_PATH,
                       "org.freedesktop.Secret.Service", "OpenSession");
        if (r < 0)
                goto finish;
        if ((r = sd_bus_message_append(request, "s", "plain")) < 0 ||
            (r = sd_bus_message_open_container(request, 'v', "s")) < 0 ||
            (r = sd_bus_message_append(request, "s", "")) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0)
                goto finish;
        if ((r = call(bus, request, &error, &reply)) < 0)
                goto finish;
        if ((r = sd_bus_message_skip(reply, "v")) < 0 ||
            (r = sd_bus_message_read(reply, "o", &path)) < 0)
                goto finish;
        if (!(*ret = strdup(path)))
                r = -ENOMEM;

finish:
        if (r < 0)
                fprintf(stderr, "OpenSession failed: %s\n",
                        error.message ?: strerror(-r));
        sd_bus_error_free(&error);
        sd_bus_message_unref(request);
        sd_bus_message_unref(reply);
        return r;
}

static int expect_error(sd_bus *bus, sd_bus_message *request, const char *name) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = NULL;
        int r;

        r = call(bus, request, &error, &reply);
        if (r >= 0 || !sd_bus_error_has_name(&error, name)) {
                fprintf(stderr, "Expected %s, got %s\n", name,
                        error.name ?: "success");
                r = -EINVAL;
        } else
                r = 0;

        sd_bus_error_free(&error);
        sd_bus_message_unref(reply);
        return r;
}

static int close_session(sd_bus *bus, const char *path, const char *expected_error) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *request = NULL, *reply = NULL;
        int r;

        r = new_method(bus, &request, path, "org.freedesktop.Secret.Session", "Close");
        if (r < 0)
                goto finish;
        if (expected_error)
                r = expect_error(bus, request, expected_error);
        else {
                r = call(bus, request, &error, &reply);
                if (r < 0)
                        fprintf(stderr, "Session.Close failed: %s\n",
                                error.message ?: strerror(-r));
        }

finish:
        sd_bus_error_free(&error);
        sd_bus_message_unref(request);
        sd_bus_message_unref(reply);
        return r;
}

static int get_secrets(sd_bus *bus, const char *session, const char *expected_error) {
        sd_bus_message *request = NULL;
        int r;

        r = new_method(bus, &request, SECRETS_PATH,
                       "org.freedesktop.Secret.Service", "GetSecrets");
        if (r < 0)
                goto finish;
        if ((r = sd_bus_message_open_container(request, 'a', "o")) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_append(request, "o", session)) < 0)
                goto finish;
        r = expect_error(bus, request, expected_error);

finish:
        sd_bus_message_unref(request);
        return r;
}

static int lock_or_unlock(sd_bus *bus, const char *member, char **ret_prompt) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *request = NULL, *reply = NULL;
        const char *prompt;
        int r;

        r = new_method(bus, &request, SECRETS_PATH,
                       "org.freedesktop.Secret.Service", member);
        if (r < 0)
                goto finish;
        if ((r = sd_bus_message_open_container(request, 'a', "o")) < 0 ||
            (r = sd_bus_message_append(request, "o", COLLECTION_PATH)) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = call(bus, request, &error, &reply)) < 0)
                goto finish;

        if (ret_prompt) {
                if ((r = sd_bus_message_skip(reply, "ao")) < 0 ||
                    (r = sd_bus_message_read(reply, "o", &prompt)) < 0)
                        goto finish;
                if (!(*ret_prompt = strdup(prompt)))
                        r = -ENOMEM;
        }

finish:
        if (r < 0)
                fprintf(stderr, "%s failed: %s\n", member,
                        error.message ?: strerror(-r));
        sd_bus_error_free(&error);
        sd_bus_message_unref(request);
        sd_bus_message_unref(reply);
        return r;
}

static int dismiss_prompt(sd_bus *bus, const char *path, const char *expected_error) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *request = NULL, *reply = NULL;
        int r;

        r = new_method(bus, &request, path, "org.freedesktop.Secret.Prompt", "Dismiss");
        if (r < 0)
                goto finish;
        if (expected_error)
                r = expect_error(bus, request, expected_error);
        else
                r = call(bus, request, &error, &reply);

finish:
        if (r < 0 && !expected_error)
                fprintf(stderr, "Prompt.Dismiss failed: %s\n",
                        error.message ?: strerror(-r));
        sd_bus_error_free(&error);
        sd_bus_message_unref(request);
        sd_bus_message_unref(reply);
        return r;
}

static int create_item(sd_bus *bus, const char *session, const char *key,
                       const char *value, char **ret_path, const char *expected_error) {
        static const char secret[] = "test-secret";
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *request = NULL, *reply = NULL;
        const char *item, *prompt;
        int r;

        r = new_method(bus, &request, COLLECTION_PATH,
                       "org.freedesktop.Secret.Collection", "CreateItem");
        if (r < 0)
                goto finish;
        if ((r = sd_bus_message_open_container(request, 'a', "{sv}")) < 0 ||
            (r = sd_bus_message_open_container(request, 'e', "sv")) < 0 ||
            (r = sd_bus_message_append(request, "s",
                                       "org.freedesktop.Secret.Item.Attributes")) < 0 ||
            (r = sd_bus_message_open_container(request, 'v', "a{ss}")) < 0 ||
            (r = sd_bus_message_open_container(request, 'a', "{ss}")) < 0 ||
            (r = sd_bus_message_append(request, "{ss}", key, value)) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_open_container(request, 'r', "oayays")) < 0 ||
            (r = sd_bus_message_append(request, "o", session)) < 0 ||
            (r = sd_bus_message_append_array(request, 'y', NULL, 0)) < 0 ||
            (r = sd_bus_message_append_array(request, 'y', secret, sizeof(secret) - 1)) < 0 ||
            (r = sd_bus_message_append(request, "s", "text/plain")) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_append(request, "b", false)) < 0)
                goto finish;

        if (expected_error) {
                r = expect_error(bus, request, expected_error);
                goto finish;
        }
        if ((r = call(bus, request, &error, &reply)) < 0 ||
            (r = sd_bus_message_read(reply, "oo", &item, &prompt)) < 0)
                goto finish;
        if (!(*ret_path = strdup(item)))
                r = -ENOMEM;

finish:
        if (r < 0 && !expected_error)
                fprintf(stderr, "CreateItem failed: %s\n",
                        error.message ?: strerror(-r));
        sd_bus_error_free(&error);
        sd_bus_message_unref(request);
        sd_bus_message_unref(reply);
        return r;
}

static int get_secret(sd_bus *bus, const char *item, const char *session,
                      const char *expected_error) {
        sd_bus_message *request = NULL;
        int r;

        r = new_method(bus, &request, item, "org.freedesktop.Secret.Item", "GetSecret");
        if (r >= 0)
                r = sd_bus_message_append(request, "o", session);
        if (r >= 0)
                r = expect_error(bus, request, expected_error);
        sd_bus_message_unref(request);
        return r;
}

static int create_collection_expect_failure(sd_bus *bus) {
        sd_bus_message *request = NULL;
        int r;

        r = new_method(bus, &request, SECRETS_PATH,
                       "org.freedesktop.Secret.Service", "CreateCollection");
        if (r < 0)
                goto finish;
        if ((r = sd_bus_message_open_container(request, 'a', "{sv}")) < 0 ||
            (r = sd_bus_message_open_container(request, 'e', "sv")) < 0 ||
            (r = sd_bus_message_append(request, "s",
                                       "org.freedesktop.Secret.Collection.Label")) < 0 ||
            (r = sd_bus_message_open_container(request, 'v', "s")) < 0 ||
            (r = sd_bus_message_append(request, "s", "persistence-test")) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_close_container(request)) < 0 ||
            (r = sd_bus_message_append(request, "s", "")) < 0)
                goto finish;
        r = expect_error(bus, request, SD_BUS_ERROR_FAILED);

finish:
        sd_bus_message_unref(request);
        return r;
}

int main(int argc, char **argv) {
        sd_bus *owner = NULL, *other = NULL;
        char *session = NULL, *orphan = NULL, *prompt = NULL, *item = NULL;
        int r;

        if ((r = sd_bus_open_user(&owner)) < 0 ||
            (r = sd_bus_open_user(&other)) < 0) {
                fprintf(stderr, "Cannot connect to the test bus: %s\n", strerror(-r));
                goto finish;
        }

        if (argc > 1 && strcmp(argv[1], "persistence") == 0) {
                r = create_collection_expect_failure(owner);
                goto finish;
        }

        if ((r = open_plain_session(owner, &session)) < 0 ||
            (r = close_session(other, session, SD_BUS_ERROR_ACCESS_DENIED)) < 0 ||
            (r = get_secrets(other, session, SD_BUS_ERROR_ACCESS_DENIED)) < 0 ||
            (r = create_item(owner, session, "platformd.policy", "unsupported",
                             NULL, SD_BUS_ERROR_INVALID_ARGS)) < 0 ||
            (r = create_item(owner, session, "platformd.min-grade", "systemd-unit",
                             &item, NULL)) < 0 ||
            (r = get_secret(owner, item, session, SD_BUS_ERROR_ACCESS_DENIED)) < 0 ||
            (r = lock_or_unlock(owner, "Lock", NULL)) < 0 ||
            (r = lock_or_unlock(owner, "Unlock", &prompt)) < 0 ||
            (r = dismiss_prompt(other, prompt, SD_BUS_ERROR_ACCESS_DENIED)) < 0 ||
            (r = dismiss_prompt(owner, prompt, NULL)) < 0 ||
            (r = open_plain_session(owner, &orphan)) < 0)
                goto finish;

        owner = sd_bus_flush_close_unref(owner);
        for (unsigned i = 0; i < 100; i++) {
                r = close_session(other, orphan, SD_BUS_ERROR_UNKNOWN_OBJECT);
                if (r == 0)
                        break;
                if (i == 99)
                        goto finish;
        }

        puts("PASS: client-owned objects and fail-closed policies");
        r = 0;

finish:
        free(session);
        free(orphan);
        free(prompt);
        free(item);
        sd_bus_flush_close_unref(owner);
        sd_bus_flush_close_unref(other);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
