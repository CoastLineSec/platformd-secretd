/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define main secretd_main
#include "secretd.c"
#undef main

static unsigned fault;

ssize_t __real_write(int fd, const void *data, size_t size);
int __real_fsync(int fd);
int __real_rename(const char *from, const char *to);

ssize_t __wrap_write(int fd, const void *data, size_t size) {
        if (fault == 1) {
                errno = EIO;
                return -1;
        }
        return __real_write(fd, data, size);
}

int __wrap_fsync(int fd) {
        struct stat st;

        assert(fstat(fd, &st) == 0);
        if ((fault == 2 && S_ISREG(st.st_mode)) || (fault == 4 && S_ISDIR(st.st_mode))) {
                errno = EIO;
                return -1;
        }
        return __real_fsync(fd);
}

int __wrap_rename(const char *from, const char *to) {
        if (fault == 3) {
                errno = EIO;
                return -1;
        }
        return __real_rename(from, to);
}

static int on_reply(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        sd_bus_message **reply = userdata;

        assert(!*reply);
        *reply = sd_bus_message_ref(message);
        return 0;
}

static void create_collection(sd_bus *client, sd_event *event, const char *alias, const char *label,
                              bool invalid_type, const char *expected_error, const char *expected_path) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *call = NULL, *reply = NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        const char *path, *prompt;

        assert(sd_bus_message_new_method_call(client, &call, SECRETS_NAME, SECRETS_PATH,
                                              "org.freedesktop.Secret.Service", "CreateCollection") >= 0);
        assert(sd_bus_message_open_container(call, 'a', "{sv}") >= 0);
        if (invalid_type)
                assert(sd_bus_message_append(call, "{sv}", "org.freedesktop.Secret.Collection.Label", "b", true) >= 0);
        else if (label)
                assert(sd_bus_message_append(call, "{sv}", "org.freedesktop.Secret.Collection.Label", "s", label) >= 0);
        assert(sd_bus_message_close_container(call) >= 0);
        assert(sd_bus_message_append(call, "s", alias) >= 0);
        assert(sd_bus_call_async(client, &slot, call, on_reply, &reply, 2000000) >= 0);
        for (unsigned i = 0; !reply && i < 100; i++)
                assert(sd_event_run(event, 100U * 1000U) >= 0);
        assert(reply);
        if (expected_error)
                assert(sd_bus_message_is_method_error(reply, expected_error));
        else {
                assert(!sd_bus_message_is_method_error(reply, NULL));
                assert(sd_bus_message_read(reply, "oo", &path, &prompt) > 0);
                assert(streq(path, expected_path));
                assert(streq(prompt, "/"));
        }
}

static void assert_store_equal(const char *path, SensitiveBuffer *before) {
        _cleanup_(sensitive_buffer_clear) SensitiveBuffer after = {};

        assert(read_file(path, &after.data, &after.size) == 0);
        assert(before->size == after.size);
        assert(memcmp(before->data, after.data, before->size) == 0);
}

int main(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL, *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *service_slot = NULL;
        _cleanup_(sensitive_buffer_clear) SensitiveBuffer before = {}, after = {};
        _cleanup_free_ char *path = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Manager manager = { .lock_fd = -1, .store_lock_fd = -1, .login_available = true };
        Collection *collection, *session;
        uint64_t modified;
        int exit_code;

        assert(sd_bus_open_user(&bus) >= 0);
        assert(sd_bus_open_user(&client) >= 0);
        assert(sd_event_new(&event) >= 0);
        assert(sd_bus_attach_event(bus, event, 0) >= 0);
        assert(sd_bus_attach_event(client, event, 0) >= 0);
        assert(sd_bus_request_name(bus, SECRETS_NAME, 0) >= 0);
        manager.bus = bus;
        manager_instance = &manager;
        collection = collection_new(&manager, COLLECTION_PATH, "original");
        session = collection_new(&manager, SESSION_COLLECTION_PATH, "Session");
        assert(collection && session);
        collection->modified = 1;
        assert(alias_set(&manager, "fixture", collection->path) >= 0);
        assert(alias_set(&manager, "session", session->path) >= 0);
        assert(sd_bus_add_object_vtable(bus, &service_slot, SECRETS_PATH,
                                        "org.freedesktop.Secret.Service", service_vtable, &manager) >= 0);
        assert(manager_save() == 0);
        assert(store_path(&path) == 0);
        assert(read_file(path, &before.data, &before.size) == 0);

        create_collection(client, event, "fixture", NULL, false, NULL, collection->path);
        assert(streq(collection->label, "original") && collection->modified == 1);
        assert_store_equal(path, &before);
        create_collection(client, event, "fixture", NULL, true, SD_BUS_ERROR_INVALID_ARGS, NULL);
        assert(streq(collection->label, "original") && collection->modified == 1);
        assert_store_equal(path, &before);

        manager.manual_locked = true;
        create_collection(client, event, "fixture", "denied", false, "org.freedesktop.Secret.Error.IsLocked", NULL);
        create_collection(client, event, "fixture", NULL, false, NULL, collection->path);
        assert(streq(collection->label, "original") && collection->modified == 1);
        assert_store_equal(path, &before);
        manager.manual_locked = false;

        g_store_readonly = true;
        create_collection(client, event, "fixture", "denied", false, SD_BUS_ERROR_FAILED, NULL);
        create_collection(client, event, "fixture", NULL, false, NULL, collection->path);
        assert(streq(collection->label, "original") && collection->modified == 1);
        assert_store_equal(path, &before);
        create_collection(client, event, "session", "volatile", false, NULL, session->path);
        assert(streq(session->label, "volatile"));
        assert_store_equal(path, &before);
        g_store_readonly = false;

        for (unsigned phase = 1; phase <= 3; phase++) {
                fault = phase;
                create_collection(client, event, "fixture", "rejected", false, SD_BUS_ERROR_FAILED, NULL);
                fault = 0;
                assert(streq(collection->label, "original") && collection->modified == 1);
                assert_store_equal(path, &before);
        }
        create_collection(client, event, "fixture", "updated", false, NULL, collection->path);
        assert(streq(collection->label, "updated") && collection->modified > 1);
        assert(manager.collections == session && session->next == collection && !collection->next);
        modified = collection->modified;
        free(collection->label);
        collection->label = strdup("reset");
        assert(collection->label);
        manager_load(&manager);
        assert(streq(collection->label, "updated") && collection->modified == modified);
        create_collection(client, event, "fixture", "", false, NULL, collection->path);
        assert(streq(collection->label, ""));

        sensitive_buffer_clear(&before);
        assert(read_file(path, &before.data, &before.size) == 0);
        modified = collection->modified;
        fault = 4;
        assert(collection_update_label(collection, "uncertain", &error) < 0);
        fault = 0;
        assert(streq(collection->label, "") && collection->modified == modified);
        assert(g_store_readonly && g_store_uncertain && g_store_error == EUCLEAN);
        assert(sd_event_get_exit_code(event, &exit_code) == 0 && exit_code == EXIT_FAILURE);
        assert(read_file(path, &after.data, &after.size) == 0);
        assert(after.size != before.size || memcmp(after.data, before.data, before.size) != 0);
        assert(memmem(after.data, after.size, "uncertain", 9));
        manager_clear(&manager);
        manager_instance = NULL;
        puts("PASS: existing alias properties, locking, persistence, and rollback");
        return EXIT_SUCCESS;
}
