/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define sd_uid_get_display test_uid_get_display
#define main secretd_main
#include "secretd.c"
#undef main
#undef sd_uid_get_display

#define TEST_SESSION_PATH "/org/freedesktop/login1/session/test"
#define OTHER_SESSION_PATH "/org/freedesktop/login1/session/other"
#define SESSION_INTERFACE "org.freedesktop.login1.Session"

int test_uid_get_display(uid_t uid, char **ret_session) {
        return -ENODATA;
}

static int on_barrier(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        *(bool *) userdata = true;
        return 0;
}

static void dispatch_signal(sd_bus *sender, sd_bus_message *message, sd_event *event, bool *barrier) {
        *barrier = false;
        assert(sd_bus_send(sender, message, NULL) >= 0);
        assert(sd_bus_emit_signal(sender, TEST_SESSION_PATH, "io.platformd.Test", "Barrier", NULL) >= 0);
        assert(sd_bus_flush(sender) >= 0);

        for (unsigned i = 0; !*barrier && i < 100; i++)
                assert(sd_event_run(event, 100U * 1000U) >= 0);
        assert(*barrier);
}

static void send_request(sd_bus *sender, sd_event *event, bool *barrier,
                         const char *path, const char *member) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

        assert(sd_bus_message_new_signal(sender, &message, path, SESSION_INTERFACE, member) >= 0);
        dispatch_signal(sender, message, event, barrier);
}

typedef enum PropertyChange {
        PROPERTY_UNLOCKED,
        PROPERTY_LOCKED,
        PROPERTY_INVALIDATED,
        PROPERTY_UNRELATED,
        PROPERTY_WRONG_TYPE,
        PROPERTY_DUPLICATE,
} PropertyChange;

static void send_property(sd_bus *sender, sd_event *event, bool *barrier,
                          const char *path, const char *interface, PropertyChange change) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

        assert(sd_bus_message_new_signal(sender, &message, path,
                                         "org.freedesktop.DBus.Properties", "PropertiesChanged") >= 0);
        assert(sd_bus_message_append(message, "s", interface) >= 0);
        assert(sd_bus_message_open_container(message, 'a', "{sv}") >= 0);
        if (change != PROPERTY_INVALIDATED) {
                const char *name = change == PROPERTY_UNRELATED ? "Active" : "LockedHint";
                const char *type = change == PROPERTY_WRONG_TYPE ? "s" : "b";

                for (unsigned i = 0; i < (change == PROPERTY_DUPLICATE ? 2U : 1U); i++) {
                        assert(sd_bus_message_open_container(message, 'e', "sv") >= 0);
                        assert(sd_bus_message_append(message, "s", name) >= 0);
                        assert(sd_bus_message_open_container(message, 'v', type) >= 0);
                        if (change == PROPERTY_WRONG_TYPE)
                                assert(sd_bus_message_append(message, "s", "false") >= 0);
                        else
                                assert(sd_bus_message_append(message, "b", change == PROPERTY_LOCKED) >= 0);
                        assert(sd_bus_message_close_container(message) >= 0);
                        assert(sd_bus_message_close_container(message) >= 0);
                }
        }
        assert(sd_bus_message_close_container(message) >= 0);
        assert(sd_bus_message_open_container(message, 'a', "s") >= 0);
        if (change == PROPERTY_INVALIDATED)
                assert(sd_bus_message_append(message, "s", "LockedHint") >= 0);
        assert(sd_bus_message_close_container(message) >= 0);
        dispatch_signal(sender, message, event, barrier);
}

int main(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *sender = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        Manager manager = {};
        bool barrier = false;

        assert(sd_event_new(&event) >= 0);
        assert(sd_bus_open_user(&sender) >= 0);
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        manager.bus = sender;
        manager_instance = &manager;
        setup_logind_lock(&manager, event);
        assert(manager.system_bus);
        assert(sd_bus_match_signal(manager.system_bus, NULL, "org.freedesktop.login1", TEST_SESSION_PATH,
                                    "io.platformd.Test", "Barrier", on_barrier, &barrier) >= 0);
        manager.my_session = strdup(TEST_SESSION_PATH);
        assert(manager.my_session);

        send_request(sender, event, &barrier, OTHER_SESSION_PATH, "Lock");
        assert(!collection_locked(&manager));
        send_request(sender, event, &barrier, TEST_SESSION_PATH, "Lock");
        assert(collection_locked(&manager));
        send_request(sender, event, &barrier, TEST_SESSION_PATH, "Unlock");
        assert(collection_locked(&manager));

        send_property(sender, event, &barrier, OTHER_SESSION_PATH, SESSION_INTERFACE, PROPERTY_UNLOCKED);
        assert(collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, "io.platformd.Test", PROPERTY_UNLOCKED);
        assert(collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_WRONG_TYPE);
        assert(collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_DUPLICATE);
        assert(collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_UNRELATED);
        assert(collection_locked(&manager));

        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_UNLOCKED);
        assert(!collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_WRONG_TYPE);
        assert(collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_UNLOCKED);
        assert(!collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_DUPLICATE);
        assert(collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_UNLOCKED);
        assert(!collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_LOCKED);
        assert(collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_UNLOCKED);
        assert(!collection_locked(&manager));
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_INVALIDATED);
        assert(collection_locked(&manager));
        send_request(sender, event, &barrier, TEST_SESSION_PATH, "Unlock");
        assert(collection_locked(&manager));

        manager.manual_locked = true;
        send_property(sender, event, &barrier, TEST_SESSION_PATH, SESSION_INTERFACE, PROPERTY_UNLOCKED);
        assert(!manager.desktop_locked);
        assert(collection_locked(&manager));

        manager.manual_locked = false;
        assert(!collection_locked(&manager));
        {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

                assert(sd_bus_message_new_signal(sender, &message, "/org/freedesktop/login1",
                                                 "org.freedesktop.login1.Manager", "SessionRemoved") >= 0);
                assert(sd_bus_message_append(message, "so", "test", TEST_SESSION_PATH) >= 0);
                dispatch_signal(sender, message, event, &barrier);
        }
        assert(collection_locked(&manager));
        assert(!manager.my_session);

        manager.system_bus = sd_bus_flush_close_unref(manager.system_bus);
        free(manager.my_session);
        manager_instance = NULL;
        puts("PASS: lock requests and confirmed LockedHint transitions");
        return EXIT_SUCCESS;
}
