/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define SECRETD_TESTING
#define sd_uid_get_sessions test_uid_get_sessions
#define sd_session_get_uid test_session_get_uid
#define sd_session_get_class test_session_get_class
#define sd_session_get_state test_session_get_state
#define main secretd_main
#include "secretd.c"
#undef main
#undef sd_uid_get_sessions
#undef sd_session_get_uid
#undef sd_session_get_class
#undef sd_session_get_state

static const char *const *test_sessions;
static int test_failure;

int test_uid_get_sessions(uid_t uid, int require_active, char ***ret) {
        size_t n = 0;

        assert(uid == getuid());
        assert(require_active == 0);
        if (test_failure)
                return -EIO;
        while (test_sessions && test_sessions[n])
                n++;
        *ret = calloc(n + 1, sizeof(char *));
        assert(*ret);
        for (size_t i = 0; i < n; i++) {
                (*ret)[i] = strdup(test_sessions[i]);
                assert((*ret)[i]);
        }
        return (int) n;
}

int test_session_get_uid(const char *session, uid_t *ret) {
        *ret = streq(session, "foreign") ? getuid() + 1 : getuid();
        return 0;
}

int test_session_get_class(const char *session, char **ret) {
        if (streq(session, "unknown"))
                return -ENODATA;
        *ret = strdup(streq(session, "manager") ? "manager" :
                      streq(session, "greeter") ? "greeter" : "user");
        return *ret ? 0 : -ENOMEM;
}

int test_session_get_state(const char *session, char **ret) {
        if (streq(session, "unknown-state"))
                return -ENODATA;
        *ret = strdup(streq(session, "closing") ? "closing" : "active");
        return *ret ? 0 : -ENOMEM;
}

static Item *add_item(Manager *manager, const char *collection) {
        Item *item = calloc(1, sizeof(Item));

        assert(item);
        item->label = strdup("volatile-label");
        item->content_type = strdup("text/plain");
        item->collection = strdup(collection);
        item->secret = memdup("volatile-secret", 15);
        item->secret_len = 15;
        assert(item->label && item->content_type && item->collection && item->secret);
        assert(manager_register_item(manager, item) >= 0);
        return item;
}

static void assert_empty(Manager *manager) {
        for (Item *item = manager->items; item; item = item->next)
                assert(!collection_volatile(item->collection));
}

typedef struct MutationTest {
        sd_event_source *grant;
        const char *const *next_sessions;
        MutationKind kind;
        bool expect_success;
        bool completed;
} MutationTest;

static int on_policy_grant(sd_event_source *source, void *userdata) {
        MutationTest *test = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        Mutation *mutation = manager_instance->mutations;

        assert(mutation);
        assert(manager_instance->login_available);
        test_sessions = test->next_sessions;
        test->grant = sd_event_source_unref(test->grant);
        assert(sd_json_buildo(&reply,
                              SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_OBJECT(
                                      SD_JSON_BUILD_PAIR_STRING("policyId", "fresh-user-verification"),
                                      SD_JSON_BUILD_PAIR_STRING("sessionId", "test-mutation"),
                                      SD_JSON_BUILD_PAIR_STRING("result", "policy-satisfied"),
                                      SD_JSON_BUILD_PAIR_STRING("reasonCode", "verification-fresh"),
                                      SD_JSON_BUILD_PAIR_STRING("reason", "Verification is fresh"),
                                      SD_JSON_BUILD_PAIR_UNSIGNED("windowSec", 60)))) >= 0);
        assert(mutation_policy_reply(NULL, reply, NULL, 0, mutation) >= 0);
        assert(!manager_instance->mutations);
        return 0;
}

static int on_pending_mutation(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        MutationTest *test = userdata;
        Mutation *mutation = calloc(1, sizeof(Mutation));

        assert(mutation);
        assert(!manager_instance->mutations);
        mutation->call = sd_bus_message_ref(message);
        mutation->owner = strdup(sd_bus_message_get_sender(message));
        mutation->session = strdup("test-mutation");
        mutation->policy = "fresh-user-verification";
        mutation->kind = test->kind;
        mutation->uid = getuid();
        mutation->revision = manager_instance->revision;
        mutation->deadline_usec = UINT64_MAX;
        assert(mutation->owner && mutation->session);
        manager_instance->mutations = mutation;
        assert(sd_event_add_defer(sd_bus_get_event(manager_instance->bus), &test->grant,
                                  on_policy_grant, test) >= 0);
        return 1;
}

static int on_mutation_reply(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        MutationTest *test = userdata;

        if (test->expect_success)
                assert(!sd_bus_message_is_method_error(message, NULL));
        else
                assert(sd_bus_message_is_method_error(message, "org.freedesktop.Secret.Error.IsLocked"));
        test->completed = true;
        return 0;
}

static const sd_bus_vtable mutation_test_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("SetLabel", "ssv", NULL, on_pending_mutation, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CreateItem", "a{sv}(oayays)b", "oo", on_pending_mutation, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

static void test_deferred_mutations(Manager *manager, sd_event *event) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *client = NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *collection_slot = NULL;
        const char *const first[] = { "first", NULL };
        const char *const second[] = { "second", NULL };
        MutationTest test = {};
        Session *transport = calloc(1, sizeof(Session));
        const char *owner;

        assert(transport);
        assert(setenv("SECRETD_TEST_SESSION_ID", "test-mutation", 1) == 0);
        assert(sd_bus_open_user(&client) >= 0);
        assert(sd_bus_attach_event(client, event, 0) >= 0);
        assert(sd_bus_get_unique_name(client, &owner) >= 0);
        transport->path = strdup(SECRETS_PATH "/session/test");
        transport->owner = strdup(owner);
        assert(transport->path && transport->owner);
        manager->sessions = transport;
        assert(sd_bus_request_name(manager->bus, SECRETS_NAME, 0) >= 0);
        assert(sd_bus_add_object_vtable(manager->bus, &collection_slot, SESSION_COLLECTION_PATH,
                                        "io.platformd.Test", mutation_test_vtable, &test) >= 0);

        for (unsigned kind = 0; kind < 2; kind++)
                for (unsigned change = 0; change < 3; change++) {
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *call = NULL;
                        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *call_slot = NULL, *item_slot = NULL;
                        Item *item;
                        uint64_t revision;

                        test_sessions = first;
                        refresh_session_collection(manager);
                        item = add_item(manager, SESSION_COLLECTION_PATH);
                        item->attrs = calloc(1, sizeof(Attr));
                        assert(item->attrs);
                        item->attrs->key = strdup("platformd.policy");
                        item->attrs->val = strdup("fresh-verification");
                        assert(item->attrs->key && item->attrs->val);
                        assert(sd_bus_add_object_vtable(manager->bus, &item_slot, item->path,
                                                        "io.platformd.Test", mutation_test_vtable, &test) >= 0);
                        test.kind = kind == 0 ? MUTATION_PROPERTY : MUTATION_CREATE_ITEM;
                        test.next_sessions = change == 0 ? first : change == 1 ? second : NULL;
                        test.expect_success = change == 0;
                        test.completed = false;
                        revision = manager->revision;
                        assert(sd_bus_message_new_method_call(client, &call, SECRETS_NAME,
                                                              kind == 0 ? item->path : SESSION_COLLECTION_PATH,
                                                              "io.platformd.Test", kind == 0 ? "SetLabel" : "CreateItem") >= 0);
                        if (kind == 0)
                                assert(sd_bus_message_append(call, "ssv", "org.freedesktop.Secret.Item",
                                                              "Label", "s", "changed") >= 0);
                        else {
                                assert(sd_bus_message_append(call, "a{sv}", 2,
                                                              "org.freedesktop.Secret.Item.Label", "s", "changed",
                                                              "org.freedesktop.Secret.Item.Attributes", "a{ss}", 1,
                                                              "platformd.policy", "fresh-verification") >= 0);
                                assert(append_secret(call, transport, (const uint8_t *) "changed", 7, "text/plain") >= 0);
                                assert(sd_bus_message_append(call, "b", true) >= 0);
                        }
                        assert(sd_bus_call_async(client, &call_slot, call, on_mutation_reply, &test, 2000000) >= 0);
                        for (unsigned i = 0; !test.completed && i < 100; i++)
                                assert(sd_event_run(event, 100U * 1000U) >= 0);
                        assert(test.completed);
                        assert(!test.grant);
                        assert(!manager->mutations);
                        assert(manager->items == item);
                        assert(streq(item->label, test.expect_success ? "changed" : "volatile-label"));
                        if (!test.expect_success) {
                                assert(manager->revision == revision);
                                assert(item->secret_len == 15 && memcmp(item->secret, "volatile-secret", 15) == 0);
                        }
                        item_slot = sd_bus_slot_unref(item_slot);
                        item_destroy(manager, item);
                }
        assert(unsetenv("SECRETD_TEST_SESSION_ID") == 0);
        session_free(manager, transport);
}

typedef struct DeletionTest {
        char *items[2];
        bool deleted[3][2];
        unsigned updates[3];
        unsigned remaining[3];
} DeletionTest;

static int on_collection_deleted(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        DeletionTest *test = userdata;
        const char *path = sd_bus_message_get_path(message), *name;
        unsigned index;
        int r;

        if (streq(path, SESSION_COLLECTION_PATH))
                index = 0;
        else if (streq(path, SECRETS_PATH "/aliases/session"))
                index = 1;
        else if (streq(path, SECRETS_PATH "/aliases/volatile"))
                index = 2;
        else
                return 0;
        if (sd_bus_message_is_signal(message, "org.freedesktop.Secret.Collection", "ItemDeleted")) {
                assert(sd_bus_message_read(message, "o", &path) > 0);
                for (unsigned i = 0; i < 2; i++)
                        if (streq(path, test->items[i])) {
                                assert(!test->deleted[index][i]);
                                test->deleted[index][i] = true;
                                return 0;
                        }
                assert(false);
        }
        if (!sd_bus_message_is_signal(message, "org.freedesktop.DBus.Properties", "PropertiesChanged"))
                return 0;
        assert(sd_bus_message_read(message, "s", &name) > 0);
        assert(streq(name, "org.freedesktop.Secret.Collection"));
        assert(sd_bus_message_enter_container(message, 'a', "{sv}") > 0);
        while ((r = sd_bus_message_enter_container(message, 'e', "sv")) > 0) {
                assert(sd_bus_message_read(message, "s", &name) > 0);
                if (streq(name, "Items")) {
                        unsigned count = 0;

                        assert(sd_bus_message_enter_container(message, 'v', "ao") > 0);
                        assert(sd_bus_message_enter_container(message, 'a', "o") > 0);
                        while ((r = sd_bus_message_read(message, "o", &path)) > 0) {
                                bool found = false;

                                for (unsigned i = 0; i < 2; i++)
                                        if (streq(path, test->items[i])) {
                                                assert(!test->deleted[index][i]);
                                                found = true;
                                        }
                                assert(found);
                                count++;
                        }
                        assert(r == 0);
                        assert(sd_bus_message_exit_container(message) > 0);
                        assert(sd_bus_message_exit_container(message) > 0);
                        test->updates[index]++;
                        test->remaining[index] = count;
                } else
                        assert(sd_bus_message_skip(message, "v") > 0);
                assert(sd_bus_message_exit_container(message) > 0);
        }
        assert(r == 0);
        return 0;
}

static void test_deletion_signals(Manager *manager, sd_event *event) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *client = NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *match = NULL, *collection_slot = NULL, *alias_slot = NULL;
        Collection *collection = manager_find_collection(manager, SESSION_COLLECTION_PATH);
        DeletionTest test = {};
        Item *persistent;

        assert(sd_bus_open_user(&client) >= 0);
        assert(sd_bus_attach_event(client, event, 0) >= 0);
        assert(sd_bus_add_object_vtable(manager->bus, &collection_slot, collection->path,
                                        "org.freedesktop.Secret.Collection", collection_vtable, collection) >= 0);
        assert(sd_bus_add_fallback_vtable(manager->bus, &alias_slot, SECRETS_PATH "/aliases",
                                          "org.freedesktop.Secret.Collection", collection_vtable,
                                          alias_resolve, manager) >= 0);
        assert(sd_bus_add_match(client, &match, "type='signal',sender='org.freedesktop.secrets'",
                                on_collection_deleted, &test) >= 0);
        assert(alias_set(manager, "volatile", SESSION_COLLECTION_PATH) >= 0);
        for (unsigned i = 0; i < 2; i++) {
                test.items[i] = strdup(add_item(manager, SESSION_COLLECTION_PATH)->path);
                assert(test.items[i]);
        }
        persistent = add_item(manager, COLLECTION_PATH);
        clear_session_collection(manager);
        for (unsigned i = 0; i < 100 &&
             (test.updates[0] < 2 || test.updates[1] < 2 || test.updates[2] < 2); i++)
                assert(sd_event_run(event, 100U * 1000U) >= 0);
        for (unsigned i = 0; i < 3; i++) {
                assert(test.deleted[i][0] && test.deleted[i][1]);
                assert(test.updates[i] == 2);
                assert(test.remaining[i] == 0);
        }
        assert(manager->items == persistent);
        assert(!alias_find(manager, "volatile"));
        item_destroy(manager, persistent);
        for (unsigned i = 0; i < 2; i++)
                free(test.items[i]);
}

int main(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        Manager manager = { .lock_fd = -1, .store_lock_fd = -1, .logind_available = true };
        const char *const first[] = { "first", NULL };
        const char *const concurrent[] = { "first", "second", NULL };
        const char *const second[] = { "second", NULL };
        const char *const third[] = { "third", NULL };
        const char *const linger[] = { "manager", "greeter", NULL };
        const char *const foreign[] = { "foreign", NULL };
        const char *const unknown[] = { "unknown", NULL };
        const char *const closing[] = { "closing", NULL };
        const char *const unknown_state[] = { "unknown-state", NULL };
        Item *item;
        Buf serialized = {};

        assert(sd_bus_open_user(&bus) >= 0);
        assert(sd_event_new(&event) >= 0);
        assert(sd_bus_attach_event(bus, event, 0) >= 0);
        manager.bus = bus;
        manager_instance = &manager;
        assert(collection_new(&manager, COLLECTION_PATH, "Default"));
        assert(collection_new(&manager, SESSION_COLLECTION_PATH, "Session"));
        assert(alias_set(&manager, "session", SESSION_COLLECTION_PATH) >= 0);
        assert(sd_login_monitor_new("session", &manager.login_monitor) >= 0);

        test_sessions = first;
        refresh_session_collection(&manager);
        assert(manager.login_available);
        item = add_item(&manager, SESSION_COLLECTION_PATH);
        assert(alias_set(&manager, "volatile-alias", SESSION_COLLECTION_PATH) >= 0);
        assert(manager_serialize(&manager, &serialized) >= 0);
        assert(!memmem(serialized.data, serialized.len, "volatile", 8));
        assert(!memmem(serialized.data, serialized.len, "session", 7));
        free(serialized.data);
        g_store_readonly = true;
        assert(collection_save(item->collection) >= 0);
        assert(manager_save() == -EROFS);
        g_store_readonly = false;

        test_sessions = concurrent;
        refresh_session_collection(&manager);
        assert(manager.items == item);
        test_sessions = second;
        refresh_session_collection(&manager);
        assert(manager.items == item);
        assert(session_collection_current(&manager));
        test_sessions = third;
        assert(!session_collection_current(&manager));
        refresh_session_collection(&manager);
        assert_empty(&manager);
        assert(manager.login_available);
        assert(!alias_find(&manager, "volatile-alias"));

        add_item(&manager, SESSION_COLLECTION_PATH);
        test_sessions = linger;
        refresh_session_collection(&manager);
        assert_empty(&manager);
        assert(!manager.login_available);
        assert(collection_path_locked(&manager, SESSION_COLLECTION_PATH));
        assert(!collection_path_locked(&manager, COLLECTION_PATH));

        for (unsigned i = 0; i < 6; i++) {
                test_sessions = first;
                refresh_session_collection(&manager);
                add_item(&manager, SESSION_COLLECTION_PATH);
                test_sessions = i == 0 ? NULL : i == 1 ? foreign : i == 2 ? unknown :
                                i == 4 ? closing : i == 5 ? unknown_state : first;
                test_failure = i == 3;
                refresh_session_collection(&manager);
                assert_empty(&manager);
                assert(!manager.login_available);
                test_failure = 0;
        }

        test_sessions = first;
        refresh_session_collection(&manager);
        add_item(&manager, SESSION_COLLECTION_PATH);
        {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

                assert(sd_bus_message_new_signal(bus, &message, "/org/freedesktop/DBus",
                                                 "org.freedesktop.DBus", "NameOwnerChanged") >= 0);
                assert(sd_bus_message_append(message, "sss", "org.freedesktop.login1", ":1.42", "") >= 0);
                assert(sd_bus_message_seal(message, 1, 0) >= 0);
                assert(sd_bus_message_rewind(message, true) >= 0);
                assert(on_logind_owner(message, &manager, NULL) >= 0);
        }
        assert_empty(&manager);
        assert(!manager.login_available);
        refresh_session_collection(&manager);
        assert(!manager.login_available);
        for (unsigned i = 0; i < 2; i++) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

                assert(sd_bus_message_new_signal(bus, &message, "/org/freedesktop/DBus",
                                                 "org.freedesktop.DBus", "OwnerQuery") >= 0);
                assert(sd_bus_message_append(message, "s", i == 0 ? ":1.42" : "invalid") >= 0);
                assert(sd_bus_message_seal(message, 2 + i, 0) >= 0);
                assert(sd_bus_message_rewind(message, true) >= 0);
                assert(on_logind_query(message, &manager, NULL) >= 0);
                assert(manager.login_available == (i == 0));
                if (i == 0)
                        add_item(&manager, SESSION_COLLECTION_PATH);
        }
        assert_empty(&manager);
        assert(manager.logind_retry);
        manager.logind_available = true;
        refresh_session_collection(&manager);
        add_item(&manager, SESSION_COLLECTION_PATH);
        assert(on_login_change(NULL, -1, EPOLLHUP, &manager) >= 0);
        assert_empty(&manager);
        assert(!manager.login_available);
        assert(!manager.login_monitor);
        assert(sd_login_monitor_new("session", &manager.login_monitor) >= 0);
        manager.logind_available = true;
        test_deferred_mutations(&manager, event);
        test_deletion_signals(&manager, event);
        manager_clear(&manager);
        manager_instance = NULL;
        puts("PASS: volatile storage, concurrent sessions, logout, linger, and logind loss");
        return EXIT_SUCCESS;
}
