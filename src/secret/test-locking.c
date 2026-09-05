/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-bus.h>

#define SECRETS_NAME "org.freedesktop.secrets"
#define SECRETS_PATH "/org/freedesktop/secrets"
#define COLLECTION_PATH SECRETS_PATH "/collection/default"
#define ALIAS_PATH SECRETS_PATH "/aliases/default"
#define SERVICE_INTERFACE "org.freedesktop.Secret.Service"
#define COLLECTION_INTERFACE "org.freedesktop.Secret.Collection"
#define ITEM_INTERFACE "org.freedesktop.Secret.Item"
#define ERROR_LOCKED "org.freedesktop.Secret.Error.IsLocked"
#define _cleanup_(f) __attribute__((cleanup(f)))

static void freep(void *p) {
        free(*(void **) p);
}

static void call(sd_bus *bus, sd_bus_message *message, const char *expected_error, sd_bus_message **ret_reply) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        r = sd_bus_call(bus, message, 5U * 1000000U, &error, &reply);
        if (expected_error) {
                if (r >= 0 || !sd_bus_error_has_name(&error, expected_error)) {
                        fprintf(stderr, "%s: expected %s, received %s\n",
                                sd_bus_message_get_member(message), expected_error, error.name ?: "success");
                        abort();
                }
        } else {
                if (r < 0) {
                        fprintf(stderr, "%s failed: %s\n", sd_bus_message_get_member(message),
                                error.message ?: strerror(-r));
                        abort();
                }
                if (ret_reply)
                        *ret_reply = sd_bus_message_ref(reply);
        }
}

static sd_bus_message *new_method(sd_bus *bus, const char *path, const char *interface, const char *member) {
        sd_bus_message *message = NULL;

        assert(sd_bus_message_new_method_call(bus, &message, SECRETS_NAME, path, interface, member) >= 0);
        return message;
}

static char *open_session(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL, *reply = NULL;
        const char *path;
        char *result;

        message = new_method(bus, SECRETS_PATH, SERVICE_INTERFACE, "OpenSession");
        assert(sd_bus_message_append(message, "sv", "plain", "s", "") >= 0);
        call(bus, message, NULL, &reply);
        assert(sd_bus_message_skip(reply, "v") >= 0);
        assert(sd_bus_message_read(reply, "o", &path) > 0);
        result = strdup(path);
        assert(result);
        return result;
}

static void append_secret(sd_bus_message *message, const char *session, const char *value) {
        assert(sd_bus_message_open_container(message, 'r', "oayays") >= 0);
        assert(sd_bus_message_append(message, "o", session) >= 0);
        assert(sd_bus_message_append_array(message, 'y', NULL, 0) >= 0);
        assert(sd_bus_message_append_array(message, 'y', value, strlen(value)) >= 0);
        assert(sd_bus_message_append(message, "s", "text/plain") >= 0);
        assert(sd_bus_message_close_container(message) >= 0);
}

static char *create_item(sd_bus *bus, const char *collection, const char *session,
                         bool protected, bool replace, const char *expected_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL, *reply = NULL;
        const char *path, *prompt;
        char *result;

        message = new_method(bus, collection, COLLECTION_INTERFACE, "CreateItem");
        assert(sd_bus_message_open_container(message, 'a', "{sv}") >= 0);
        assert(sd_bus_message_append(message, "{sv}", ITEM_INTERFACE ".Label", "s", "Original label") >= 0);
        assert(sd_bus_message_open_container(message, 'e', "sv") >= 0);
        assert(sd_bus_message_append(message, "s", ITEM_INTERFACE ".Attributes") >= 0);
        assert(sd_bus_message_open_container(message, 'v', "a{ss}") >= 0);
        assert(sd_bus_message_open_container(message, 'a', "{ss}") >= 0);
        assert(sd_bus_message_append(message, "{ss}", "test", "locking") >= 0);
        if (protected)
                assert(sd_bus_message_append(message, "{ss}", "platformd.min-grade", "same-user-weak") >= 0);
        assert(sd_bus_message_close_container(message) >= 0);
        assert(sd_bus_message_close_container(message) >= 0);
        assert(sd_bus_message_close_container(message) >= 0);
        assert(sd_bus_message_close_container(message) >= 0);
        append_secret(message, session, replace ? "replacement-secret" : "original-secret");
        assert(sd_bus_message_append(message, "b", replace) >= 0);
        call(bus, message, expected_error, &reply);
        if (expected_error)
                return NULL;

        assert(sd_bus_message_read(reply, "oo", &path, &prompt) > 0);
        assert(strcmp(prompt, "/") == 0);
        result = strdup(path);
        assert(result);
        return result;
}

static char *create_collection(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL, *reply = NULL;
        const char *path, *prompt;
        char *result;

        message = new_method(bus, SECRETS_PATH, SERVICE_INTERFACE, "CreateCollection");
        assert(sd_bus_message_append(message, "a{sv}s", 1,
                                     COLLECTION_INTERFACE ".Label", "s", "Lock test", "") >= 0);
        call(bus, message, NULL, &reply);
        assert(sd_bus_message_read(reply, "oo", &path, &prompt) > 0);
        assert(strcmp(prompt, "/") == 0);
        result = strdup(path);
        assert(result);
        return result;
}

static void set_secret(sd_bus *bus, const char *item, const char *session, const char *expected_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

        message = new_method(bus, item, ITEM_INTERFACE, "SetSecret");
        append_secret(message, session, "updated-secret");
        call(bus, message, expected_error, NULL);
}

static void set_label(sd_bus *bus, const char *item, const char *expected_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

        message = new_method(bus, item, "org.freedesktop.DBus.Properties", "Set");
        assert(sd_bus_message_append(message, "ssv", ITEM_INTERFACE, "Label", "s", "Updated label") >= 0);
        call(bus, message, expected_error, NULL);
}

static void set_attributes(sd_bus *bus, const char *item, const char *expected_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

        message = new_method(bus, item, "org.freedesktop.DBus.Properties", "Set");
        assert(sd_bus_message_append(message, "ssv", ITEM_INTERFACE, "Attributes", "a{ss}", 1,
                                     "test", "changed") >= 0);
        call(bus, message, expected_error, NULL);
}

static void delete_object(sd_bus *bus, const char *path, const char *interface, const char *expected_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

        message = new_method(bus, path, interface, "Delete");
        call(bus, message, expected_error, NULL);
}

static void check_locked(sd_bus *bus, const char *path, const char *interface, bool expected) {
        int locked;

        assert(sd_bus_get_property_trivial(bus, SECRETS_NAME, path, interface, "Locked", NULL, 'b', &locked) >= 0);
        assert((bool) locked == expected);
}

static void check_metadata(sd_bus *bus, const char *item, bool protected) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(freep) char *label = NULL;
        const char *key, *value;
        unsigned n = 0;

        assert(sd_bus_get_property_string(bus, SECRETS_NAME, item, ITEM_INTERFACE, "Label", NULL, &label) >= 0);
        assert(strcmp(label, "Original label") == 0);
        assert(sd_bus_get_property(bus, SECRETS_NAME, item, ITEM_INTERFACE, "Attributes", NULL, &reply, "a{ss}") >= 0);
        assert(sd_bus_message_enter_container(reply, 'a', "{ss}") > 0);
        while (sd_bus_message_read(reply, "{ss}", &key, &value) > 0) {
                if (strcmp(key, "test") == 0)
                        assert(strcmp(value, "locking") == 0);
                else {
                        assert(protected);
                        assert(strcmp(key, "platformd.min-grade") == 0);
                        assert(strcmp(value, "same-user-weak") == 0);
                }
                n++;
        }
        assert(n == (protected ? 2U : 1U));
}

static void test_locked_mutations(sd_bus *bus, const char *collection, const char *item,
                                  const char *session, bool protected) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

        check_locked(bus, collection, COLLECTION_INTERFACE, true);
        check_locked(bus, item, ITEM_INTERFACE, true);
        assert(!create_item(bus, collection, session, protected, false, ERROR_LOCKED));
        assert(!create_item(bus, collection, session, protected, true, ERROR_LOCKED));
        set_secret(bus, item, session, ERROR_LOCKED);
        set_attributes(bus, item, ERROR_LOCKED);
        set_label(bus, item, ERROR_LOCKED);
        delete_object(bus, item, ITEM_INTERFACE, ERROR_LOCKED);
        delete_object(bus, collection, COLLECTION_INTERFACE, ERROR_LOCKED);
        check_metadata(bus, item, protected);

        message = new_method(bus, item, ITEM_INTERFACE, "GetSecret");
        assert(sd_bus_message_append(message, "o", session) >= 0);
        call(bus, message, ERROR_LOCKED, NULL);
}

int main(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(freep) char *session = NULL, *collection = NULL, *empty_collection = NULL;
        _cleanup_(freep) char *ordinary = NULL, *protected = NULL, *mutable = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

        assert(sd_bus_open_user(&bus) >= 0);
        session = open_session(bus);
        collection = create_collection(bus);
        empty_collection = create_collection(bus);
        ordinary = create_item(bus, COLLECTION_PATH, session, false, false, NULL);
        protected = create_item(bus, collection, session, true, false, NULL);
        mutable = create_item(bus, empty_collection, session, false, false, NULL);
        check_locked(bus, COLLECTION_PATH, COLLECTION_INTERFACE, false);
        set_secret(bus, mutable, session, NULL);
        set_label(bus, mutable, NULL);
        set_attributes(bus, mutable, NULL);
        delete_object(bus, mutable, ITEM_INTERFACE, NULL);

        message = new_method(bus, SECRETS_PATH, SERVICE_INTERFACE, "Lock");
        assert(sd_bus_message_append(message, "ao", 1, COLLECTION_PATH) >= 0);
        call(bus, message, NULL, NULL);
        test_locked_mutations(bus, COLLECTION_PATH, ordinary, session, false);
        test_locked_mutations(bus, collection, protected, session, true);
        assert(!create_item(bus, ALIAS_PATH, session, false, false, ERROR_LOCKED));
        delete_object(bus, empty_collection, COLLECTION_INTERFACE, ERROR_LOCKED);

        puts("PASS: locked collections reject ordinary and protected mutations");
        return EXIT_SUCCESS;
}
