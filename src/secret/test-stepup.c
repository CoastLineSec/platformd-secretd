/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define SECRETD_TESTING
#define main secretd_main
#include "secretd.c"
#undef main

#define TEST_SESSION "/org/freedesktop/secrets/session/test"
#define TEST_FRESH COLLECTION_PATH "/fresh"
#define TEST_TRUSTED COLLECTION_PATH "/trusted"
#define TEST_ORDINARY COLLECTION_PATH "/ordinary"

typedef struct TestState {
        sd_event *event;
        bool expect_locked;
        bool completed;
        unsigned destroyed_sources;
        int peer_fd;
} TestState;

static TestState *test_instance;

static void on_source_destroy(void *userdata) {
        test_instance->destroyed_sources++;
}

static int on_retry(sd_event_source *source, uint64_t usec, void *userdata) {
        assert(false);
        return 0;
}

static int on_get_secrets(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        static const char *const paths[] = { TEST_FRESH, TEST_TRUSTED, TEST_ORDINARY };
        static const char *const policies[] = { "fresh-verification", "trusted-platform", "" };
        TestState *state = userdata;
        StepUp *su;
        int pair[2];

        assert(manager_instance->stepups == NULL);
        su = calloc(1, sizeof *su);
        assert(su);
        su->call = sd_bus_message_ref(message);
        su->owner = strdup(sd_bus_message_get_sender(message));
        su->xport_session = strdup(TEST_SESSION);
        su->session = strdup("test-stepup");
        assert(su->owner && su->xport_session && su->session);
        su->uid = getuid();
        su->grade = CALLER_SAME_USER_WEAK;
        su->bulk = true;
        su->phase = STEPUP_VERIFY;
        su->n_bulk_paths = sizeof paths / sizeof paths[0];
        su->bulk_paths = calloc(su->n_bulk_paths, sizeof *su->bulk_paths);
        su->bulk_item_policy_snapshots = calloc(su->n_bulk_paths, sizeof *su->bulk_item_policy_snapshots);
        su->bulk_items_present = calloc(su->n_bulk_paths, sizeof *su->bulk_items_present);
        assert(su->bulk_paths && su->bulk_item_policy_snapshots && su->bulk_items_present);
        for (size_t i = 0; i < su->n_bulk_paths; i++) {
                su->bulk_paths[i] = strdup(paths[i]);
                su->bulk_item_policy_snapshots[i] = strdup(policies[i]);
                assert(su->bulk_paths[i] && su->bulk_item_policy_snapshots[i]);
                su->bulk_items_present[i] = true;
        }
        su->n_bulk_policies = 2;
        su->bulk_trust_policies[0] = strdup("fresh-user-verification");
        su->bulk_trust_policies[1] = strdup("local-trusted-session");
        assert(su->bulk_trust_policies[0] && su->bulk_trust_policies[1]);
        su->bulk_allowed[0] = su->bulk_allowed[1] = true;
        manager_instance->stepups = su;

        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair) == 0);
        assert(sd_varlink_connect_fd(&su->vl, pair[0]) >= 0);
        state->peer_fd = pair[1];
        assert(sd_varlink_attach_event(su->vl, state->event, SD_EVENT_PRIORITY_NORMAL) >= 0);
        assert(sd_event_add_time_relative(state->event, &su->retry, CLOCK_MONOTONIC,
                                          60U * 1000000U, 0, on_retry, su) >= 0);
        assert(sd_event_source_set_destroy_callback(su->retry, on_source_destroy) >= 0);
        assert(sd_event_add_time_relative(state->event, &su->deadline, CLOCK_MONOTONIC,
                                          0, 0, stepup_deadline, su) >= 0);
        assert(sd_event_source_set_destroy_callback(su->deadline, on_source_destroy) >= 0);
        return 1;
}

static int on_reply(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        TestState *state = userdata;

        if (state->expect_locked)
                assert(sd_bus_message_is_method_error(message, "org.freedesktop.Secret.Error.IsLocked"));
        else {
                const void *parameters, *value;
                const char *path, *session, *content_type;
                size_t parameters_size, value_size;

                assert(!sd_bus_message_is_method_error(message, NULL));
                assert(sd_bus_message_enter_container(message, 'a', "{o(oayays)}") > 0);
                assert(sd_bus_message_enter_container(message, 'e', "o(oayays)") > 0);
                assert(sd_bus_message_read(message, "o", &path) > 0);
                assert(streq(path, TEST_ORDINARY));
                assert(sd_bus_message_enter_container(message, 'r', "oayays") > 0);
                assert(sd_bus_message_read(message, "o", &session) > 0);
                assert(streq(session, TEST_SESSION));
                assert(sd_bus_message_read_array(message, 'y', &parameters, &parameters_size) >= 0);
                assert(parameters_size == 0);
                assert(sd_bus_message_read_array(message, 'y', &value, &value_size) >= 0);
                assert(value_size == strlen("test-secret"));
                assert(memcmp(value, "test-secret", value_size) == 0);
                assert(sd_bus_message_read(message, "s", &content_type) > 0);
                assert(streq(content_type, "text/plain"));
                assert(sd_bus_message_exit_container(message) >= 0);
                assert(sd_bus_message_exit_container(message) >= 0);
                assert(sd_bus_message_enter_container(message, 'e', "o(oayays)") == 0);
                assert(sd_bus_message_exit_container(message) >= 0);
                assert(sd_bus_message_at_end(message, true) > 0);
        }
        state->completed = true;
        return 0;
}

static const sd_bus_vtable test_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("GetSecrets", "aoo", "a{o(oayays)}", on_get_secrets, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

int main(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *server = NULL, *client = NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        uint8_t value[] = "test-secret";
        Attr fresh_policy = { .key = "platformd.policy", .val = "fresh-verification" };
        Attr trusted_policy = { .key = "platformd.policy", .val = "trusted-platform" };
        Item ordinary = {
                .path = TEST_ORDINARY,
                .secret = value,
                .secret_len = sizeof value - 1,
                .content_type = "text/plain",
        };
        Item trusted = {
                .next = &ordinary,
                .path = TEST_TRUSTED,
                .attrs = &trusted_policy,
                .secret = value,
                .secret_len = sizeof value - 1,
                .content_type = "text/plain",
        };
        Item fresh = {
                .next = &trusted,
                .path = TEST_FRESH,
                .attrs = &fresh_policy,
                .secret = value,
                .secret_len = sizeof value - 1,
                .content_type = "text/plain",
        };
        Session session = { .path = TEST_SESSION };
        Manager manager = { .sessions = &session, .items = &fresh };
        TestState state = { .peer_fd = -1 };
        const char *owner;

        assert(sd_event_new(&event) >= 0);
        assert(sd_bus_open_user(&server) >= 0);
        assert(sd_bus_open_user(&client) >= 0);
        assert(sd_bus_get_unique_name(client, &owner) >= 0);
        session.owner = strdup(owner);
        assert(session.owner);
        assert(sd_bus_request_name(server, SECRETS_NAME, 0) >= 0);
        assert(sd_bus_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL) >= 0);
        assert(sd_bus_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL) >= 0);
        manager.bus = server;
        manager_instance = &manager;
        state.event = event;
        test_instance = &state;
        assert(sd_bus_add_object_vtable(server, &slot, SECRETS_PATH,
                                        "org.freedesktop.Secret.Service", test_vtable, &state) >= 0);

        for (unsigned i = 0; i < 2; i++) {
                _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *call_slot = NULL;
                char byte;

                state.expect_locked = manager.manual_locked = i > 0;
                state.completed = false;
                state.destroyed_sources = 0;
                assert(sd_bus_call_method_async(client, &call_slot, SECRETS_NAME, SECRETS_PATH,
                                                "org.freedesktop.Secret.Service", "GetSecrets", on_reply,
                                                &state, "aoo", 3, TEST_FRESH, TEST_TRUSTED, TEST_ORDINARY,
                                                TEST_SESSION) >= 0);
                for (unsigned j = 0; !state.completed && j < 100; j++)
                        assert(sd_event_run(event, 100U * 1000U) >= 0);
                assert(state.completed);
                assert(!manager.stepups);
                assert(state.destroyed_sources == 2);
                assert(read(state.peer_fd, &byte, sizeof byte) == 0);
                assert(close(state.peer_fd) == 0);
                state.peer_fd = -1;
        }

        slot = sd_bus_slot_unref(slot);
        assert(sd_bus_detach_event(client) >= 0);
        assert(sd_bus_detach_event(server) >= 0);
        free(session.owner);
        vault_wipe(value, sizeof value);
        manager_instance = NULL;
        test_instance = NULL;
        puts("PASS: bulk deadlines discard policy decisions and cancel pending work");
        return EXIT_SUCCESS;
}
