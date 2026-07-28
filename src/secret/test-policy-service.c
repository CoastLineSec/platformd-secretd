/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))

typedef struct Fake Fake;

typedef struct PendingReply {
        struct PendingReply *next;
        Fake *fake;
        sd_varlink *link;
        sd_bus_message *message;
        sd_event_source *timer;
        char *cancel_id;
        bool polkit;
} PendingReply;

struct Fake {
        sd_event *event;
        sd_varlink_server *server;
        sd_bus *bus;
        const char *mode;
        unsigned trust_calls;
        unsigned verify_calls;
        unsigned polkit_calls;
        unsigned cancel_calls;
        PendingReply *pending;
};

static Fake *fake_instance;

static void pending_free(PendingReply *pending) {
        if (!pending)
                return;
        for (PendingReply **p = &pending->fake->pending; *p; p = &(*p)->next)
                if (*p == pending) {
                        *p = pending->next;
                        break;
                }
        sd_event_source_unref(pending->timer);
        sd_varlink_unref(pending->link);
        sd_bus_message_unref(pending->message);
        free(pending->cancel_id);
        free(pending);
}

static const char *json_string(sd_json_variant *parameters, const char *name) {
        sd_json_variant *value = parameters ? sd_json_variant_by_key(parameters, name) : NULL;
        return value && sd_json_variant_is_string(value) ? sd_json_variant_string(value) : NULL;
}

static int reply_policy(
                sd_varlink *link,
                const char *policy,
                const char *session,
                bool satisfied,
                const char *reason_code) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = NULL, *reply = NULL;
        int r;

        if ((r = sd_json_buildo(
                             &record,
                             SD_JSON_BUILD_PAIR("policyId", SD_JSON_BUILD_STRING(policy)),
                             SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(session)),
                             SD_JSON_BUILD_PAIR(
                                             "result",
                                             SD_JSON_BUILD_STRING(
                                                             satisfied ? "policy-satisfied" : "denied")),
                             SD_JSON_BUILD_PAIR(
                                             "reasonCode",
                                             SD_JSON_BUILD_STRING(reason_code)),
                             SD_JSON_BUILD_PAIR("reason", SD_JSON_BUILD_STRING("test policy result")),
                             SD_JSON_BUILD_PAIR("windowSec", SD_JSON_BUILD_UNSIGNED(300)))) < 0 ||
            (r = sd_json_buildo(
                             &reply,
                             SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_VARIANT(record)))) < 0)
                return r;
        return sd_varlink_reply(link, reply);
}

static int evaluate_policy(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Fake *fake = fake_instance;
        const char *policy = json_string(parameters, "policy");
        const char *session = json_string(parameters, "sessionId");
        bool satisfied = false;
        const char *reason = "verification-stale";

        (void) flags;
        fake->trust_calls++;
        if (!policy || !session)
                return sd_varlink_error_invalid_parameter_name(link, "policy");
        if (streq(fake->mode, "malformed"))
                return sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR("unexpected", SD_JSON_BUILD_BOOLEAN(true)));
        if (streq(fake->mode, "satisfied"))
                satisfied = true;
        else if (streq(fake->mode, "stale-then-success") ||
                 streq(fake->mode, "verify-delay") ||
                 streq(fake->mode, "verify-malformed"))
                satisfied = fake->trust_calls > 1;
        else if (streq(fake->mode, "stale-delayed"))
                satisfied = fake->trust_calls > 4;
        else if (streq(fake->mode, "locked"))
                reason = "session-locked";

        return reply_policy(
                        link,
                        policy,
                        session,
                        satisfied,
                        satisfied
                                ? (streq(policy, "fresh-user-verification")
                                                ? "verification-fresh"
                                                : "local-trusted-session")
                                : reason);
}

static int delayed_verify(sd_event_source *source, uint64_t usec, void *userdata) {
        PendingReply *pending = userdata;

        pending->timer = sd_event_source_unref(pending->timer);
        (void) sd_varlink_replybo(
                        pending->link,
                        SD_JSON_BUILD_PAIR("verified", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR("method", SD_JSON_BUILD_STRING("platformd-verify")),
                        SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(1)));
        pending_free(pending);
        return 0;
}

static int verify_user(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Fake *fake = fake_instance;

        (void) parameters;
        (void) flags;
        fake->verify_calls++;
        if (streq(fake->mode, "verify-malformed"))
                return sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR("verified", SD_JSON_BUILD_BOOLEAN(true)));
        if (streq(fake->mode, "verify-delay")) {
                PendingReply *pending = calloc(1, sizeof *pending);
                if (!pending)
                        return -ENOMEM;
                pending->fake = fake;
                pending->link = sd_varlink_ref(link);
                pending->next = fake->pending;
                fake->pending = pending;
                if (sd_event_add_time_relative(
                                    fake->event,
                                    &pending->timer,
                                    CLOCK_MONOTONIC,
                                    2U * 1000000U,
                                    10U * 1000U,
                                    delayed_verify,
                                    pending) < 0) {
                        pending_free(pending);
                        return -ENOMEM;
                }
                return 1;
        }
        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "verified",
                                        SD_JSON_BUILD_BOOLEAN(!streq(fake->mode, "verify-decline"))),
                        SD_JSON_BUILD_PAIR("method", SD_JSON_BUILD_STRING("platformd-verify")),
                        SD_JSON_BUILD_PAIR("realtimeUSec", SD_JSON_BUILD_UNSIGNED(1)));
}

static int get_stats(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Fake *fake = fake_instance;

        (void) parameters;
        (void) flags;
        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "trustCalls",
                                        SD_JSON_BUILD_UNSIGNED(fake->trust_calls)),
                        SD_JSON_BUILD_PAIR(
                                        "verifyCalls",
                                        SD_JSON_BUILD_UNSIGNED(fake->verify_calls)),
                        SD_JSON_BUILD_PAIR(
                                        "polkitCalls",
                                        SD_JSON_BUILD_UNSIGNED(fake->polkit_calls)),
                        SD_JSON_BUILD_PAIR(
                                        "cancelCalls",
                                        SD_JSON_BUILD_UNSIGNED(fake->cancel_calls)));
}

static int delayed_polkit(sd_event_source *source, uint64_t usec, void *userdata) {
        PendingReply *pending = userdata;

        pending->timer = sd_event_source_unref(pending->timer);
        (void) sd_bus_reply_method_return(
                        pending->message,
                        "(bba{ss})",
                        true,
                        false,
                        0);
        pending_free(pending);
        return 0;
}

static int polkit_check(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Fake *fake = userdata;
        PendingReply *pending;
        const char *subject, *action, *cancel_id;
        uint32_t flags;
        int r;

        (void) flags;
        fake->polkit_calls++;
        if ((r = sd_bus_message_enter_container(message, 'r', "sa{sv}")) < 0 ||
            (r = sd_bus_message_read(message, "s", &subject)) < 0 ||
            (r = sd_bus_message_skip(message, "a{sv}")) < 0 ||
            (r = sd_bus_message_exit_container(message)) < 0 ||
            (r = sd_bus_message_read(message, "s", &action)) < 0 ||
            (r = sd_bus_message_skip(message, "a{ss}")) < 0 ||
            (r = sd_bus_message_read(message, "us", &flags, &cancel_id)) < 0)
                return r;
        if (!streq(action, "io.platformd.secret1.unlock-collection"))
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Unexpected action");

        pending = calloc(1, sizeof *pending);
        if (!pending)
                return -ENOMEM;
        pending->fake = fake;
        pending->message = sd_bus_message_ref(message);
        pending->cancel_id = strdup(cancel_id);
        pending->polkit = true;
        pending->next = fake->pending;
        fake->pending = pending;
        if (!pending->cancel_id ||
            sd_event_add_time_relative(
                            fake->event,
                            &pending->timer,
                            CLOCK_MONOTONIC,
                            2U * 1000000U,
                            10U * 1000U,
                            delayed_polkit,
                            pending) < 0) {
                pending_free(pending);
                return -ENOMEM;
        }
        return 1;
}

static int polkit_cancel(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Fake *fake = userdata;
        const char *cancel_id;

        (void) error;
        if (sd_bus_message_read(message, "s", &cancel_id) < 0)
                return -EINVAL;
        fake->cancel_calls++;
        for (PendingReply *pending = fake->pending, *next; pending; pending = next) {
                next = pending->next;
                if (pending->polkit && streq(pending->cancel_id, cancel_id)) {
                        (void) sd_bus_reply_method_errorf(
                                        pending->message,
                                        "org.freedesktop.DBus.Error.Canceled",
                                        "Authorization canceled");
                        pending_free(pending);
                        break;
                }
        }
        return sd_bus_reply_method_return(message, NULL);
}

static const sd_bus_vtable polkit_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD(
                        "CheckAuthorization",
                        "(sa{sv})sa{ss}us",
                        "(bba{ss})",
                        polkit_check,
                        SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD(
                        "CancelCheckAuthorization",
                        "s",
                        NULL,
                        polkit_cancel,
                        SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

int main(int argc, char **argv) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        Fake fake = {};
        char trust[4096], verify[4096];
        int r;

        if (argc != 3)
                return EXIT_FAILURE;
        fake.mode = argv[2];
        if ((r = sd_event_default(&event)) < 0 ||
            (r = sd_varlink_server_new(&server, 0)) < 0)
                return EXIT_FAILURE;
        fake.event = event;
        fake.server = server;
        fake_instance = &fake;
        (void) sd_varlink_server_set_userdata(server, &fake);
        r = snprintf(trust, sizeof trust, "%s/trust.sock", argv[1]);
        if (r < 0 || (size_t) r >= sizeof trust)
                return EXIT_FAILURE;
        r = snprintf(verify, sizeof verify, "%s/verify.sock", argv[1]);
        if (r < 0 || (size_t) r >= sizeof verify)
                return EXIT_FAILURE;
        if ((r = sd_varlink_server_bind_method(
                             server,
                             "io.platformd.Trust.EvaluatePolicy",
                             evaluate_policy)) < 0 ||
            (r = sd_varlink_server_bind_method(
                             server,
                             "io.platformd.Verify.VerifyUser",
                             verify_user)) < 0 ||
            (r = sd_varlink_server_bind_method(
                             server,
                             "io.platformd.Test.GetStats",
                             get_stats)) < 0)
                return EXIT_FAILURE;
        if (!streq(fake.mode, "no-trust") &&
            (r = sd_varlink_server_listen_address(server, trust, 0600)) < 0)
                return EXIT_FAILURE;
        if (!streq(fake.mode, "no-verify") &&
            (r = sd_varlink_server_listen_address(server, verify, 0600)) < 0)
                return EXIT_FAILURE;
        if ((r = sd_varlink_server_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL)) < 0)
                return EXIT_FAILURE;

        if (streq(fake.mode, "polkit-delay")) {
                if ((r = sd_bus_open_user(&bus)) < 0 ||
                    (r = sd_bus_add_object_vtable(
                                     bus,
                                     NULL,
                                     "/org/freedesktop/PolicyKit1/Authority",
                                     "org.freedesktop.PolicyKit1.Authority",
                                     polkit_vtable,
                                     &fake)) < 0 ||
                    (r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL)) < 0 ||
                    (r = sd_bus_request_name(bus, "org.freedesktop.PolicyKit1", 0)) < 0)
                        return EXIT_FAILURE;
                fake.bus = bus;
        }

        (void) sd_event_add_signal(
                        event,
                        NULL,
                        SIGTERM | SD_EVENT_SIGNAL_PROCMASK,
                        NULL,
                        NULL);
        return sd_event_loop(event) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
