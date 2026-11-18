/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Command-line client for platformd-secretd. */

#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>

#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION "unknown"
#endif
#define streq(a, b) (strcmp((a), (b)) == 0)

/* sd-bus.h provides cleanup helpers for bus and message objects. */
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

/* Report the owner of org.freedesktop.secrets on the user bus. */
static void probe_secret_service(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m1 = NULL, *m2 = NULL, *m3 = NULL;
        _cleanup_free_ char *unit = NULL;
        const char *owner = NULL;
        uint32_t pid = 0;
        int r, has_owner = 0;

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                printf("  provider:  no session bus reachable (%s)\n", strerror(-r));
                return;
        }

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                               "org.freedesktop.DBus", "NameHasOwner",
                               &error, &m1, "s", "org.freedesktop.secrets");
        if (r < 0) {
                printf("  provider:  query failed (%s)\n",
                       error.message ? error.message : strerror(-r));
                return;
        }
        if (sd_bus_message_read(m1, "b", &has_owner) < 0 || !has_owner) {
                printf("  provider:  none, org.freedesktop.secrets is unclaimed\n");
                printf("             (no Secret Service provider is running on this session)\n");
                return;
        }

        if (sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                               "org.freedesktop.DBus", "GetNameOwner",
                               &error, &m2, "s", "org.freedesktop.secrets") >= 0)
                (void) sd_bus_message_read(m2, "s", &owner);

        if (owner &&
            sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                               "org.freedesktop.DBus", "GetConnectionUnixProcessID",
                               &error, &m3, "s", owner) >= 0)
                (void) sd_bus_message_read(m3, "u", &pid);

        if (pid > 0)
                (void) sd_pid_get_user_unit(pid, &unit);

        printf("  provider:  claimed, owner %s", owner ? owner : "?");
        if (pid > 0)
                printf(", pid %u", (unsigned) pid);
        if (unit)
                printf(", unit %s", unit);
        printf("\n");
}

/* logind's declared lock state for a session (login1 LockedHint property).
 * It is a declared hint, not verified. Returns
 * 1 locked, 0 unlocked, <0 unknown. */
static int session_locked_hint(const char *session) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *path;
        int locked = -1;

        if (sd_bus_open_system(&bus) < 0)
                return -1;
        if (sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
                               "org.freedesktop.login1.Manager", "GetSession",
                               &error, &reply, "s", session) < 0)
                return -1;
        if (sd_bus_message_read(reply, "o", &path) < 0)
                return -1;
        if (sd_bus_get_property_trivial(bus, "org.freedesktop.login1", path,
                                        "org.freedesktop.login1.Session", "LockedHint",
                                        &error, 'b', &locked) < 0)
                return -1;
        return locked;
}

/* Report the logind session that contains this process. */
static void probe_session(void) {
        _cleanup_free_ char *session = NULL, *seat = NULL, *type = NULL,
                            *class = NULL, *state = NULL;
        int active, locked;

        if (sd_pid_get_session(0, &session) < 0) {
                printf("  session:   none, this process is not in a logind session\n");
                return;
        }
        (void) sd_session_get_seat(session, &seat);
        (void) sd_session_get_type(session, &type);
        (void) sd_session_get_class(session, &class);
        (void) sd_session_get_state(session, &state);
        active = sd_session_is_active(session);
        locked = session_locked_hint(session);

        printf("  session:   %s  seat=%s type=%s class=%s state=%s active=%s\n",
               session, seat ? seat : "-", type ? type : "-",
               class ? class : "-", state ? state : "-",
               active > 0 ? "yes" : (active == 0 ? "no" : "?"));
        printf("  locked:    %s\n",
               locked < 0 ? "unknown" : (locked ? "yes (declared)" : "no (declared)"));
}

/* Report the identity evidence available for this process. */
static void probe_caller_identity(void) {
        _cleanup_free_ char *unit = NULL, *cgroup = NULL;
        const char *quality;

        if (sd_pid_get_user_unit(0, &unit) < 0)
                (void) sd_pid_get_unit(0, &unit);
        (void) sd_pid_get_cgroup(0, &cgroup);

        quality = "same-user-weak";

        printf("  caller:    uid=%u pid=%u unit=%s\n",
               (unsigned) getuid(), (unsigned) getpid(), unit ? unit : "-");
        printf("             cgroup=%s\n", cgroup ? cgroup : "-");
        printf("             identity evidence: %s\n", quality);
}

/* --- list / lock / unlock: talk to the running provider ------------------- */

#define SECRETS_NAME "org.freedesktop.secrets"
#define SVC_PATH     "/org/freedesktop/secrets"
#define COLL_PATH    "/org/freedesktop/secrets/collection/default"
#define IF_COLL      "org.freedesktop.Secret.Collection"
#define IF_ITEM      "org.freedesktop.Secret.Item"
#define IF_SVC       "org.freedesktop.Secret.Service"
#define IF_PROMPT    "org.freedesktop.Secret.Prompt"

static bool provider_running(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int has = 0;

        if (sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                               "org.freedesktop.DBus", "NameHasOwner", &error, &reply,
                               "s", SECRETS_NAME) < 0)
                return false;
        (void) sd_bus_message_read(reply, "b", &has);
        return has;
}

static int cmd_list(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *items = NULL;
        int r, locked = 0, count = 0;

        if (sd_bus_open_user(&bus) < 0) {
                fprintf(stderr, "secretctl: cannot connect to the session bus\n");
                return EXIT_FAILURE;
        }
        if (!provider_running(bus)) {
                printf("No Secret Service provider is running on this session.\n");
                return EXIT_SUCCESS;
        }

        (void) sd_bus_get_property_trivial(bus, SECRETS_NAME, COLL_PATH, IF_COLL,
                                           "Locked", NULL, 'b', &locked);
        printf("default collection (%s):\n", locked ? "locked" : "unlocked");

        r = sd_bus_get_property(bus, SECRETS_NAME, COLL_PATH, IF_COLL, "Items", &error, &items, "ao");
        if (r < 0) {
                fprintf(stderr, "secretctl: %s\n", error.message ? error.message : strerror(-r));
                return EXIT_FAILURE;
        }
        if (sd_bus_message_enter_container(items, 'a', "o") < 0)
                return EXIT_FAILURE;
        for (;;) {
                const char *ip;
                _cleanup_free_ char *label = NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *attrs = NULL;

                r = sd_bus_message_read(items, "o", &ip);
                if (r <= 0)
                        break;
                (void) sd_bus_get_property_string(bus, SECRETS_NAME, ip, IF_ITEM, "Label", NULL, &label);
                printf("  * %s\n", (label && *label) ? label : "(no label)");
                if (sd_bus_get_property(bus, SECRETS_NAME, ip, IF_ITEM, "Attributes", NULL, &attrs, "a{ss}") >= 0 &&
                    sd_bus_message_enter_container(attrs, 'a', "{ss}") >= 0) {
                        while (sd_bus_message_enter_container(attrs, 'e', "ss") > 0) {
                                const char *k, *v;
                                if (sd_bus_message_read(attrs, "ss", &k, &v) >= 0)
                                        printf("      %s = %s\n", k, v);
                                sd_bus_message_exit_container(attrs);
                        }
                        sd_bus_message_exit_container(attrs);
                }
                count++;
        }
        sd_bus_message_exit_container(items);
        if (count == 0)
                printf("  (no items)\n");
        return EXIT_SUCCESS;
}

static int read_handled_objects(sd_bus_message *message) {
        const char *path;
        unsigned count = 0;
        bool handled = false;
        int r;

        if ((r = sd_bus_message_enter_container(message, 'a', "o")) <= 0)
                return r < 0 ? r : -EBADMSG;
        while ((r = sd_bus_message_read(message, "o", &path)) > 0) {
                if (++count > 65536U + 4097U)
                        return -E2BIG;
                handled |= streq(path, COLL_PATH);
        }
        if (r < 0 || (r = sd_bus_message_exit_container(message)) < 0)
                return r;
        return handled;
}

static uint64_t deadline_remaining(uint64_t deadline) {
        struct timespec now;
        uint64_t usec;

        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
                return 0;
        usec = (uint64_t) now.tv_sec * 1000000U + now.tv_nsec / 1000U;
        return usec < deadline ? deadline - usec : 0;
}

static int call_before(sd_bus *bus, sd_bus_message *request, uint64_t deadline,
                       sd_bus_error *error, sd_bus_message **reply) {
        uint64_t remaining = deadline_remaining(deadline);

        return remaining > 0 ? sd_bus_call(bus, request, remaining, error, reply) : -ETIMEDOUT;
}

struct prompt_wait { bool done; int dismissed; int handled; };

static int on_prompt_completed(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        struct prompt_wait *w = userdata;

        w->done = true;
        w->handled = -EBADMSG;
        if (sd_bus_message_read(m, "b", &w->dismissed) <= 0 ||
            sd_bus_message_enter_container(m, 'v', "ao") <= 0)
                return 0;
        w->handled = read_handled_objects(m);
        if (sd_bus_message_exit_container(m) < 0 || sd_bus_message_at_end(m, true) <= 0)
                w->handled = -EBADMSG;
        return 0;
}

static int lock_or_unlock(const char *method) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        struct timespec now;
        uint64_t deadline;
        int r, handled, locked;

        if (sd_bus_open_user(&bus) < 0) {
                fprintf(stderr, "secretctl: cannot connect to the session bus\n");
                return EXIT_FAILURE;
        }
        if (!provider_running(bus)) {
                fprintf(stderr, "secretctl: no Secret Service provider is running\n");
                return EXIT_FAILURE;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
                return EXIT_FAILURE;
        deadline = (uint64_t) now.tv_sec * 1000000U + now.tv_nsec / 1000U + 130U * 1000000U;
        r = sd_bus_message_new_method_call(bus, &req, SECRETS_NAME, SVC_PATH, IF_SVC, method);
        if (r < 0 ||
            sd_bus_message_open_container(req, 'a', "o") < 0 ||
            sd_bus_message_append(req, "o", COLL_PATH) < 0 ||
            sd_bus_message_close_container(req) < 0)
                return EXIT_FAILURE;
        if (call_before(bus, req, deadline, &error, &reply) < 0) {
                fprintf(stderr, "secretctl: %s\n", error.message ? error.message : "call failed");
                return EXIT_FAILURE;
        }

        const char *prompt;
        handled = read_handled_objects(reply);
        if (handled < 0 || sd_bus_message_read(reply, "o", &prompt) <= 0 ||
            sd_bus_message_at_end(reply, true) <= 0) {
                fprintf(stderr, "secretctl: invalid lock operation reply\n");
                return EXIT_FAILURE;
        }
        if (!streq(prompt, "/")) {
                struct prompt_wait w = {};
                _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *preq = NULL, *prep = NULL;

                uint64_t remaining = deadline_remaining(deadline);
                if (remaining == 0 || sd_bus_set_method_call_timeout(bus, remaining) < 0 ||
                    sd_bus_match_signal(bus, &slot, SECRETS_NAME, prompt, IF_PROMPT,
                                         "Completed", on_prompt_completed, &w) < 0 ||
                    sd_bus_message_new_method_call(bus, &preq, SECRETS_NAME, prompt, IF_PROMPT, "Prompt") < 0 ||
                    sd_bus_message_append(preq, "s", "") < 0 ||
                    call_before(bus, preq, deadline, &error, &prep) < 0) {
                        fprintf(stderr, "secretctl: %s\n", error.message ? error.message : "prompt failed");
                        return EXIT_FAILURE;
                }
                while (!w.done && (remaining = deadline_remaining(deadline)) > 0) {
                        r = sd_bus_process(bus, NULL);
                        if (r < 0 || (r == 0 && sd_bus_wait(bus, remaining) < 0))
                                break;
                }
                if (!w.done) {
                        fprintf(stderr, "secretctl: unlock prompt timed out\n");
                        return EXIT_FAILURE;
                }
                if (w.dismissed) {
                        fprintf(stderr, "secretctl: unlock declined\n");
                        return EXIT_FAILURE;
                }
                if (w.handled < 0) {
                        fprintf(stderr, "secretctl: invalid prompt completion result\n");
                        return EXIT_FAILURE;
                }
                handled |= w.handled;
        }
        if (!handled) {
                fprintf(stderr, "secretctl: the default collection was not %sed\n",
                        streq(method, "Lock") ? "lock" : "unlock");
                return EXIT_FAILURE;
        }
        req = sd_bus_message_unref(req);
        reply = sd_bus_message_unref(reply);
        if (sd_bus_message_new_method_call(bus, &req, SECRETS_NAME, COLL_PATH,
                                           "org.freedesktop.DBus.Properties", "Get") < 0 ||
            sd_bus_message_append(req, "ss", IF_COLL, "Locked") < 0 ||
            call_before(bus, req, deadline, &error, &reply) < 0 ||
            sd_bus_message_enter_container(reply, 'v', "b") <= 0 ||
            sd_bus_message_read(reply, "b", &locked) <= 0 ||
            sd_bus_message_exit_container(reply) < 0 || sd_bus_message_at_end(reply, true) <= 0 ||
            !!locked != streq(method, "Lock")) {
                fprintf(stderr, "secretctl: the requested collection lock state was not confirmed\n");
                return EXIT_FAILURE;
        }
        printf("default collection %sed\n", streq(method, "Lock") ? "lock" : "unlock");
        return EXIT_SUCCESS;
}

static int cmd_lock(void)   { return lock_or_unlock("Lock"); }
static int cmd_unlock(void) { return lock_or_unlock("Unlock"); }

static int cmd_status(void) {
        printf("secretctl status: read-only; nothing is claimed or stored\n\n");
        probe_secret_service();
        probe_session();
        probe_caller_identity();
        return EXIT_SUCCESS;
}

static int help(void) {
        printf("secretctl %s\n\n", PROGRAM_VERSION);
        printf("Usage:\n");
        printf("  secretctl status     Report the provider, session/lock state, and caller identity\n");
        printf("  secretctl list       List the default collection's items and attributes\n");
        printf("  secretctl lock       Lock the default collection\n");
        printf("  secretctl unlock     Unlock the default collection\n");
        printf("  secretctl version\n");
        printf("  secretctl help\n\n");
        printf("Storing and reading individual secrets is the job of secret-tool(1).\n");
        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        const char *verb = argc > 1 ? argv[1] : "help";

        if (streq(verb, "status"))
                return cmd_status();
        if (streq(verb, "list"))
                return cmd_list();
        if (streq(verb, "lock"))
                return cmd_lock();
        if (streq(verb, "unlock"))
                return cmd_unlock();
        if (streq(verb, "version") || streq(verb, "--version") || streq(verb, "-V")) {
                printf("secretctl %s\n", PROGRAM_VERSION);
                return EXIT_SUCCESS;
        }
        if (streq(verb, "help") || streq(verb, "--help") || streq(verb, "-h"))
                return help();

        fprintf(stderr, "secretctl: unknown command '%s'\n\n", verb);
        (void) help();
        return EXIT_FAILURE;
}
