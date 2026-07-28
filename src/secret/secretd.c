/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* freedesktop Secret Service provider with optional platform release policy. */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pwd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-login.h>
#include <systemd/sd-varlink.h>
#include <systemd/sd-json.h>
#include <systemd/sd-id128.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "vault.h"

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

typedef struct SensitiveBuffer {
        uint8_t *data;
        size_t size;
} SensitiveBuffer;

static void sensitive_buffer_clear(SensitiveBuffer *buffer) {
        if (!buffer->data)
                return;

        vault_wipe(buffer->data, buffer->size);
        free(buffer->data);
}

#define SECRETS_NAME    "org.freedesktop.secrets"
#define SECRETS_PATH    "/org/freedesktop/secrets"
#define COLLECTION_PATH "/org/freedesktop/secrets/collection/default"
#define COLLECTION_LABEL "Default"
#define ALIAS_PATH      "/org/freedesktop/secrets/aliases/default"   /* where libsecret looks */

typedef struct Attr {
        char *key;
        char *val;
        struct Attr *next;
} Attr;

typedef struct Item {
        struct Item *next;
        sd_bus_slot *slot;
        char *path;
        char *label;
        Attr *attrs;
        uint8_t *secret;
        size_t secret_len;
        char *content_type;
        char *collection;       /* owning collection's object path */
        uint64_t created, modified;
        bool deleted;
        bool deleting;
} Item;

typedef struct Session {
        struct Session *next;
        char *path;
        char *owner;
        sd_bus_slot *slot;      /* the Session object's vtable, unref'd on Close */
        bool encrypted;         /* the session uses the DH transport (else plain) */
        uint8_t aes_key[16];    /* AES-128 transport key when encrypted */
} Session;

typedef struct Prompt {
        struct Prompt *next;
        char *path;
        char *owner;
        char *cancel_id;
        sd_bus_slot *slot;
        sd_bus_slot *auth_slot;
} Prompt;

typedef struct StepUp StepUp;

typedef struct Collection {
        struct Collection *next;
        char *path;
        char *label;
        uint64_t created, modified;
        sd_bus_slot *slot;      /* vtable slot; NULL for the built-in default (2 paths) */
} Collection;

typedef struct Manager {
        sd_bus *bus;
        uint64_t session_seq;
        uint64_t prompt_seq;
        uint64_t item_seq;
        uint64_t coll_seq;
        uint64_t coll_created;
        bool desktop_locked;
        bool manual_locked;
        sd_bus *system_bus;
        char *my_session;
        sd_varlink_server *varlink;
        char *home_storage;
        Session *sessions;
        Prompt *prompts;
        StepUp *stepups;
        Collection *collections;
        Item *items;
} Manager;

static Manager *manager_instance;
static int manager_save(void);
static void manager_load(Manager *mgr);
static Collection *collection_new(Manager *mgr, const char *path, const char *label);
static void collection_destroy(Manager *mgr, Collection *collection);
static const sd_bus_vtable collection_vtable[];

static uint8_t g_vault_key[VAULT_KEY_LEN];
static bool g_encrypting;
static bool g_store_readonly;

static int fail(const char *what, int r) {
        sd_journal_print(LOG_ERR, "%s: %s", what, strerror(-r));
        return EXIT_FAILURE;
}

static uint64_t now_secs(void) { return (uint64_t) time(NULL); }

static void *memdup(const void *p, size_t n) {
        void *q = malloc(n ? n : 1);
        if (q && p)
                memcpy(q, p, n);
        return q;
}

/* --- attributes --- */

static void free_attrs(Attr *a) {
        while (a) {
                Attr *next = a->next;
                free(a->key);
                free(a->val);
                free(a);
                a = next;
        }
}

static int read_attrs(sd_bus_message *m, Attr **ret) {
        Attr *head = NULL, *tail = NULL;
        int r;

        r = sd_bus_message_enter_container(m, 'a', "{ss}");
        if (r < 0)
                return r;
        for (;;) {
                const char *k, *v;
                r = sd_bus_message_enter_container(m, 'e', "ss");
                if (r < 0)
                        goto fail;
                if (r == 0)
                        break;
                r = sd_bus_message_read(m, "ss", &k, &v);
                if (r < 0)
                        goto fail;
                Attr *a = calloc(1, sizeof *a);
                if (!a) { r = -ENOMEM; goto fail; }
                a->key = strdup(k);
                a->val = strdup(v);
                if (!a->key || !a->val) {
                        free(a->key); free(a->val); free(a);
                        r = -ENOMEM; goto fail;
                }
                if (tail) tail->next = a; else head = a;
                tail = a;
                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        goto fail;
        }
        r = sd_bus_message_exit_container(m);
        if (r < 0)
                goto fail;
        *ret = head;
        return 0;

fail:
        free_attrs(head);
        return r;
}

static const char *attr_get(Attr *list, const char *k) {
        for (Attr *a = list; a; a = a->next)
                if (streq(a->key, k))
                        return a->val;
        return NULL;
}

static int validate_platformd_attrs(Attr *attrs, sd_bus_error *error) {
        bool have_min_grade = false, have_policy = false;

        for (Attr *attr = attrs; attr; attr = attr->next) {
                if (streq(attr->key, "platformd.policy")) {
                        if (have_policy)
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                        "platformd.policy is specified more than once");
                        have_policy = true;
                        if (!streq(attr->val, "fresh-verification") &&
                            !streq(attr->val, "trusted-platform"))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                         "unsupported platformd.policy value '%s'",
                                                         attr->val);
                } else if (streq(attr->key, "platformd.min-grade")) {
                        if (have_min_grade)
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                        "platformd.min-grade is specified more than once");
                        have_min_grade = true;
                        if (!streq(attr->val, "same-user-weak") &&
                            !streq(attr->val, "systemd-unit") &&
                            !streq(attr->val, "sandboxed-app"))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                         "unsupported platformd.min-grade value '%s'",
                                                         attr->val);
                }
        }

        return 0;
}

/* every entry of `query` must be present with the same value in `attrs`. */
static bool attrs_match(Attr *attrs, Attr *query) {
        for (Attr *q = query; q; q = q->next) {
                const char *v = attr_get(attrs, q->key);
                if (!v || !streq(v, q->val))
                        return false;
        }
        return true;
}

static bool attrs_equal(Attr *a, Attr *b) {
        return attrs_match(a, b) && attrs_match(b, a);
}

static int append_attrs(sd_bus_message *reply, Attr *attrs) {
        int r = sd_bus_message_open_container(reply, 'a', "{ss}");
        if (r < 0)
                return r;
        for (Attr *a = attrs; a; a = a->next) {
                r = sd_bus_message_append(reply, "{ss}", a->key, a->val);
                if (r < 0)
                        return r;
        }
        return sd_bus_message_close_container(reply);
}

static Session *find_session(Manager *m, const char *path, const char *owner) {
        if (m && path && *path && owner && *owner)
                for (Session *s = m->sessions; s; s = s->next)
                        if (streq(s->path, path) && streq(s->owner, owner))
                                return s;
        return NULL;
}

/* Secret Service secret struct: (o session, ay parameters, ay value, s content-type).
 * On a DH session the value is AES-128-CBC encrypted and the IV rides in parameters. */
static int append_secret(sd_bus_message *reply, Session *session,
                         const uint8_t *value, size_t len, const char *ct) {
        _cleanup_free_ uint8_t *enc = NULL;
        const uint8_t *params = NULL, *out = value;
        size_t params_len = 0, out_len = len;
        uint8_t iv[VAULT_DH_IV_LEN];
        int r;

        if (session->encrypted) {
                if (vault_transport_encrypt(session->aes_key, value, len, iv, &enc, &out_len) < 0)
                        return -EIO;
                out = enc;
                params = iv;
                params_len = VAULT_DH_IV_LEN;
        }
        if ((r = sd_bus_message_open_container(reply, 'r', "oayays")) < 0 ||
            (r = sd_bus_message_append(reply, "o", session->path)) < 0 ||
            (r = sd_bus_message_append_array(reply, 'y', params, params_len)) < 0 ||
            (r = sd_bus_message_append_array(reply, 'y', out, out_len)) < 0 ||
            (r = sd_bus_message_append(reply, "s", (ct && *ct) ? ct : "text/plain")) < 0)
                return r;
        return sd_bus_message_close_container(reply);
}

/* --- items --- */

static Item *manager_find_by_path(Manager *m, const char *path) {
        for (Item *i = m->items; i; i = i->next)
                if (!i->deleted && streq(i->path, path))
                        return i;
        return NULL;
}

/* Emit an org.freedesktop.Secret.Collection change signal for an item. The
 * default collection is served at both its canonical and alias paths, so signal
 * on both. items_changed also flags the collection's Items property as changed. */
static void emit_item_signal(const char *collection, const char *member,
                             const char *item_path, bool items_changed) {
        Manager *mgr = manager_instance;
        const char *paths[2];
        int n = 0;

        if (!mgr)
                return;
        paths[n++] = collection ? collection : COLLECTION_PATH;
        if (streq(paths[0], COLLECTION_PATH))   /* the default is also served at the alias path */
                paths[n++] = ALIAS_PATH;
        for (int i = 0; i < n; i++) {
                (void) sd_bus_emit_signal(mgr->bus, paths[i],
                                          "org.freedesktop.Secret.Collection", member, "o", item_path);
                if (items_changed)
                        (void) sd_bus_emit_properties_changed(mgr->bus, paths[i],
                                                              "org.freedesktop.Secret.Collection", "Items", NULL);
        }
}

/* Notify that the default collection's Locked property changed (both paths). */
static void emit_locked_changed(void) {
        static const char *const paths[] = { COLLECTION_PATH, ALIAS_PATH };
        Manager *mgr = manager_instance;

        if (!mgr)
                return;
        for (size_t i = 0; i < 2; i++)
                (void) sd_bus_emit_properties_changed(mgr->bus, paths[i],
                                                      "org.freedesktop.Secret.Collection", "Locked", NULL);
}

/* Caller identity evidence is graded because same-UID credentials do not
 * establish an application identity. */

typedef enum {
        CALLER_UNKNOWN,
        CALLER_SAME_USER_WEAK,
        CALLER_SYSTEMD_UNIT,
        CALLER_SANDBOXED_APP,
} CallerGrade;

static const char *caller_grade_name(CallerGrade g) {
        switch (g) {
        case CALLER_SANDBOXED_APP:  return "sandboxed-app";
        case CALLER_SYSTEMD_UNIT:   return "systemd-unit";
        case CALLER_SAME_USER_WEAK: return "same-user-weak";
        default:                    return "unknown";
        }
}

static CallerGrade caller_grade(sd_bus_message *m, const char *event) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        CallerGrade grade = CALLER_UNKNOWN;
        uid_t uid = (uid_t) -1;
        pid_t pid = 0;
        const char *unit = NULL;

        if (sd_bus_query_sender_creds(m,
                                      SD_BUS_CREDS_UID | SD_BUS_CREDS_PID |
                                      SD_BUS_CREDS_USER_UNIT | SD_BUS_CREDS_AUGMENT,
                                      &creds) < 0 || !creds)
                return CALLER_UNKNOWN;

        (void) sd_bus_creds_get_uid(creds, &uid);
        (void) sd_bus_creds_get_pid(creds, &pid);
        (void) sd_bus_creds_get_user_unit(creds, &unit);

        /*
         * User-unit and cgroup names are caller-controlled metadata, not an
         * authenticated application identity. Until the service has a
         * verifiable identity source, every local same-UID caller receives the
         * weakest grade.
         */
        if (uid == getuid())
                grade = CALLER_SAME_USER_WEAK;

        sd_journal_send("MESSAGE=caller graded (%s): uid=%d pid=%d unit=%s grade=%s",
                        event, (int) uid, (int) pid, unit ? unit : "-", caller_grade_name(grade),
                        "PRIORITY=%i", LOG_INFO,
                        "PLATFORMD_EVENT=%s", event,
                        "PLATFORMD_CALLER_UID=%d", (int) uid,
                        "PLATFORMD_CALLER_PID=%d", (int) pid,
                        "PLATFORMD_CALLER_UNIT=%s", unit ? unit : "",
                        "PLATFORMD_CALLER_GRADE=%s", caller_grade_name(grade),
                        NULL);
        return grade;
}

static bool grade_from_name(const char *s, CallerGrade *ret) {
        if (streq(s, "sandboxed-app"))
                *ret = CALLER_SANDBOXED_APP;
        else if (streq(s, "systemd-unit"))
                *ret = CALLER_SYSTEMD_UNIT;
        else if (streq(s, "same-user-weak"))
                *ret = CALLER_SAME_USER_WEAK;
        else
                return false;
        return true;
}

/* --- platform release policy ---------------------------------------------- */

static bool collection_locked(Manager *m) {
        return m->desktop_locked || m->manual_locked;
}

static bool text_valid(const char *text, size_t max) {
        size_t n;

        if (!text)
                return false;
        n = strnlen(text, max + 1);
        if (n > max)
                return false;
        for (size_t i = 0; i < n; i++)
                if ((unsigned char) text[i] < 0x20 || (unsigned char) text[i] == 0x7f)
                        return false;
        return true;
}

static bool session_class_allowed(const char *class) {
        return class &&
               (streq(class, "user") ||
                streq(class, "user-early") ||
                streq(class, "user-light") ||
                streq(class, "user-early-light"));
}

static int session_locked_hint(sd_bus *bus, const char *session) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *path;
        int locked;

        if (!bus ||
            sd_bus_call_method(
                            bus,
                            "org.freedesktop.login1",
                            "/org/freedesktop/login1",
                            "org.freedesktop.login1.Manager",
                            "GetSession",
                            &error,
                            &reply,
                            "s",
                            session) < 0 ||
            sd_bus_message_read(reply, "o", &path) < 0 ||
            sd_bus_get_property_trivial(
                            bus,
                            "org.freedesktop.login1",
                            path,
                            "org.freedesktop.login1.Session",
                            "LockedHint",
                            &error,
                            'b',
                            &locked) < 0)
                return -EIO;
        return locked;
}

static int session_eligible(sd_bus *system_bus, const char *session, uid_t uid) {
        _cleanup_free_ char *class = NULL;
        uid_t session_uid;

#ifdef SECRETD_TESTING
        const char *forced = getenv("SECRETD_TEST_SESSION_ID");
        if (forced && streq(forced, session))
                return uid == getuid();
#endif

        if (!text_valid(session, 256) || !*session ||
            sd_session_get_uid(session, &session_uid) < 0 ||
            session_uid != uid ||
            sd_session_is_active(session) != 1 ||
            sd_session_is_remote(session) != 0 ||
            sd_session_get_class(session, &class) < 0 ||
            !session_class_allowed(class) ||
            session_locked_hint(system_bus, session) != 0)
                return 0;
        return 1;
}

static void string_vector_free(char **strings) {
        if (!strings)
                return;
        for (char **p = strings; *p; p++)
                free(*p);
        free(strings);
}

static int caller_session(sd_bus_message *message, char **ret, uid_t *ret_uid) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *system_bus = NULL;
        _cleanup_free_ char *preferred = NULL;
        char **sessions = NULL;
        pid_t pid;
        uid_t uid;
        int n, found = 0, r;

        *ret = NULL;
        if (ret_uid)
                *ret_uid = (uid_t) -1;
        if (sd_bus_query_sender_creds(
                            message,
                            SD_BUS_CREDS_EUID | SD_BUS_CREDS_PID | SD_BUS_CREDS_AUGMENT,
                            &creds) < 0 ||
            sd_bus_creds_get_euid(creds, &uid) < 0 ||
            sd_bus_creds_get_pid(creds, &pid) < 0 ||
            uid != getuid())
                return -EACCES;

#ifdef SECRETD_TESTING
        const char *forced = getenv("SECRETD_TEST_SESSION_ID");
        if (forced && text_valid(forced, 256) && *forced) {
                *ret = strdup(forced);
                if (!*ret)
                        return -ENOMEM;
                if (ret_uid)
                        *ret_uid = uid;
                return 0;
        }
#endif

        if (sd_bus_open_system(&system_bus) < 0)
                return -EHOSTUNREACH;
        (void) sd_bus_set_method_call_timeout(system_bus, 2U * 1000000U);

        if (sd_pid_get_session(pid, &preferred) >= 0 &&
            session_eligible(system_bus, preferred, uid) > 0) {
                *ret = preferred;
                preferred = NULL;
                if (ret_uid)
                        *ret_uid = uid;
                return 0;
        }

        n = sd_uid_get_sessions(uid, 1, &sessions);
        if (n < 0)
                return n;
        if (n > 64) {
                string_vector_free(sessions);
                return -ENOTUNIQ;
        }
        for (int i = 0; i < n; i++)
                if (session_eligible(system_bus, sessions[i], uid) > 0) {
                        found++;
                        if (found == 1) {
                                *ret = strdup(sessions[i]);
                                if (!*ret) {
                                        string_vector_free(sessions);
                                        return -ENOMEM;
                                }
                        }
                }
        string_vector_free(sessions);
        if (found != 1) {
                free(*ret);
                *ret = NULL;
                return found > 1 ? -ENOTUNIQ : -ENXIO;
        }
        if (ret_uid)
                *ret_uid = uid;
        r = 0;
        return r;
}

static const char *trust_policy_name(const char *item_policy) {
        if (!item_policy)
                return NULL;
        if (streq(item_policy, "fresh-verification"))
                return "fresh-user-verification";
        if (streq(item_policy, "trusted-platform"))
                return "local-trusted-session";
        return NULL;
}

static int trustd_policy_sync(const char *policy, const char *session) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *call = NULL, *parameters = NULL, *reply = NULL;
        _cleanup_free_ char *request = NULL, *buf = NULL;
        sd_json_variant *wire_parameters, *result, *value;
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        struct timeval tv = { .tv_sec = 2 };
        const char *sock;
        size_t buflen = 0, cap = 0;
        bool complete = false;
        int fd, len, r;

        if (!policy || !session || !*session)
                return -EINVAL;
        sock = getenv("PLATFORMD_TRUST_SOCKET");
        if (!sock || !*sock)
                sock = "/run/platformd-trustd/io.platformd.Trust";
        len = snprintf(sa.sun_path, sizeof sa.sun_path, "%s", sock);
        if (len < 0 || (size_t) len >= sizeof sa.sun_path)
                return -ENAMETOOLONG;

        if (sd_json_buildo(
                            &parameters,
                            SD_JSON_BUILD_PAIR("policy", SD_JSON_BUILD_STRING(policy)),
                            SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(session))) < 0 ||
            sd_json_buildo(
                            &call,
                            SD_JSON_BUILD_PAIR(
                                            "method",
                                            SD_JSON_BUILD_STRING("io.platformd.Trust.EvaluatePolicy")),
                            SD_JSON_BUILD_PAIR(
                                            "parameters",
                                            SD_JSON_BUILD_VARIANT(parameters))) < 0 ||
            sd_json_variant_format(call, 0, &request) < 0)
                return -ENOMEM;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
                r = -errno;
                close(fd);
                return r;
        }
        for (size_t written = 0, size = strlen(request) + 1; written < size;) {
                ssize_t n = write(fd, request + written, size - written);
                if (n <= 0) {
                        r = n < 0 ? -errno : -EIO;
                        close(fd);
                        return r;
                }
                written += (size_t) n;
        }
        for (;;) {
                char chunk[1024];
                ssize_t n = read(fd, chunk, sizeof chunk);
                char *nb;

                if (n < 0) {
                        r = -errno;
                        close(fd);
                        return r;
                }
                if (n == 0)
                        break;
                if (buflen + (size_t) n > 64U * 1024U) {
                        close(fd);
                        return -E2BIG;
                }
                if (buflen + (size_t) n + 1 > cap) {
                        cap = (buflen + (size_t) n + 1) * 2;
                        if (!(nb = realloc(buf, cap))) {
                                close(fd);
                                return -ENOMEM;
                        }
                        buf = nb;
                }
                memcpy(buf + buflen, chunk, (size_t) n);
                buflen += (size_t) n;
                if (memchr(chunk, 0, (size_t) n)) {
                        complete = true;
                        break;
                }
        }
        close(fd);
        if (!buf || !complete)
                return -EBADMSG;
        buf[buflen] = 0;
        if (sd_json_parse(buf, 0, &reply, NULL, NULL) < 0 || sd_json_variant_by_key(reply, "error"))
                return -EBADMSG;
        wire_parameters = sd_json_variant_by_key(reply, "parameters");
        result = wire_parameters ? sd_json_variant_by_key(wire_parameters, "result") : NULL;
        value = result ? sd_json_variant_by_key(result, "result") : NULL;
        if (!value || !sd_json_variant_is_string(value))
                return -EBADMSG;
        if (streq(sd_json_variant_string(value), "policy-satisfied"))
                return 1;
        if (streq(sd_json_variant_string(value), "denied"))
                return 0;
        return -EBADMSG;
}

typedef enum {
        GATE_ALLOW,
        GATE_LOCKED,
        GATE_CALLER,
        GATE_TRUSTD,
        GATE_POLICY,
        GATE_SESSION,
} GateResult;

static GateResult trust_gate_local(Item *item, CallerGrade grade) {
        Manager *mgr = manager_instance;
        const char *policy, *mingrade;
        CallerGrade required;

        if (collection_locked(mgr))
                return GATE_LOCKED;

        policy = attr_get(item->attrs, "platformd.policy");
        if (policy && !trust_policy_name(policy))
                return GATE_POLICY;

        mingrade = attr_get(item->attrs, "platformd.min-grade");
        if (mingrade) {
                if (!grade_from_name(mingrade, &required))
                        return GATE_POLICY;
                if (grade < required)
                        return GATE_CALLER;
        }

        return GATE_ALLOW;
}

static GateResult trust_gate(Item *item, CallerGrade grade, sd_bus_message *message) {
        _cleanup_free_ char *session = NULL;
        const char *policy;
        GateResult gate;

        gate = trust_gate_local(item, grade);
        if (gate != GATE_ALLOW)
                return gate;
        policy = trust_policy_name(attr_get(item->attrs, "platformd.policy"));
        if (!policy)
                return GATE_ALLOW;
        if (caller_session(message, &session, NULL) < 0)
                return GATE_SESSION;
        return trustd_policy_sync(policy, session) == 1 ? GATE_ALLOW : GATE_TRUSTD;
}

static bool item_protected(Item *item) {
        for (Attr *a = item->attrs; a; a = a->next)
                if (strncmp(a->key, "platformd.", 10) == 0)
                        return true;
        return false;
}

static int gate_mutation(Item *item, sd_bus_message *m, sd_bus_error *e) {
        if (!item_protected(item))
                return 0;
        if (trust_gate(item, caller_grade(m, "secret-mutate"), m) != GATE_ALLOW)
                return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                        "The item is protected and its release policy is not currently satisfied");
        return 0;
}

static uint64_t proc_starttime(pid_t pid) {
        char path[64], buf[2048], *tok, *save;
        int fd, field = 2;
        ssize_t n;
        uint64_t st = 0;

        snprintf(path, sizeof path, "/proc/%d/stat", (int) pid);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return 0;
        n = read(fd, buf, sizeof buf - 1);
        (void) close(fd);
        if (n <= 0)
                return 0;
        buf[n] = 0;
        tok = strrchr(buf, ')');   /* comm may hold spaces/parens; skip past it */
        if (!tok)
                return 0;
        for (tok = strtok_r(tok + 1, " ", &save); tok; tok = strtok_r(NULL, " ", &save))
                if (++field == 22) { st = strtoull(tok, NULL, 10); break; }
        return st;
}

typedef enum StepUpPhase {
        STEPUP_POLICY,
        STEPUP_VERIFY,
        STEPUP_POLICY_AFTER_VERIFY,
} StepUpPhase;

struct StepUp {
        StepUp *next;
        sd_bus_message *call;
        char *owner;
        char *item_path;
        char *xport_session;
        char *item_policy;
        char *trust_policy;
        char *session;
        uid_t uid;
        CallerGrade grade;
        StepUpPhase phase;
        unsigned grace_attempts;
        sd_varlink *vl;
        sd_event_source *deadline;
        sd_event_source *retry;
        char **bulk_paths;
        char **bulk_item_policy_snapshots;
        bool *bulk_items_present;
        size_t n_bulk_paths;
        char *bulk_trust_policies[2];
        char *bulk_item_paths[2];
        char *bulk_item_policies[2];
        bool bulk_allowed[2];
        size_t n_bulk_policies;
        size_t bulk_policy_index;
        bool bulk;
};

static void stepup_free(StepUp *su) {
        Manager *mgr = manager_instance;

        if (!su)
                return;
        if (mgr)
                for (StepUp **p = &mgr->stepups; *p; p = &(*p)->next)
                        if (*p == su) {
                                *p = su->next;
                                break;
                        }
        sd_varlink_unref(su->vl);
        sd_event_source_unref(su->deadline);
        sd_event_source_unref(su->retry);
        sd_bus_message_unref(su->call);
        free(su->owner);
        free(su->item_path);
        free(su->xport_session);
        free(su->item_policy);
        free(su->trust_policy);
        free(su->session);
        if (su->bulk_paths) {
                for (size_t i = 0; i < su->n_bulk_paths; i++)
                        free(su->bulk_paths[i]);
                free(su->bulk_paths);
        }
        if (su->bulk_item_policy_snapshots) {
                for (size_t i = 0; i < su->n_bulk_paths; i++)
                        free(su->bulk_item_policy_snapshots[i]);
                free(su->bulk_item_policy_snapshots);
        }
        free(su->bulk_items_present);
        for (size_t i = 0; i < su->n_bulk_policies; i++) {
                free(su->bulk_trust_policies[i]);
                free(su->bulk_item_paths[i]);
                free(su->bulk_item_policies[i]);
        }
        free(su);
}

static Session *message_session(sd_bus_message *message, const char *path, sd_bus_error *error) {
        const char *sender = sd_bus_message_get_sender(message);
        Session *session;

        if (!sender) {
                sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED,
                                 "Cannot determine the D-Bus caller");
                return NULL;
        }
        session = find_session(manager_instance, path, sender);
        if (!session)
                sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED,
                                 "The session does not belong to the caller");
        return session;
}

static int send_item_secret(sd_bus_message *call, const char *item_path, const char *xport_session) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Item *item = manager_find_by_path(manager_instance, item_path);
        Session *session;
        int r;

        if (!item)
                return sd_bus_reply_method_errorf(call, "org.freedesktop.Secret.Error.NoSuchObject",
                                                  "The item no longer exists");
        if (!(session = message_session(call, xport_session, &error)))
                return sd_bus_reply_method_error(call, &error);
        if ((r = sd_bus_message_new_method_return(call, &reply)) < 0 ||
            (r = append_secret(reply, session, item->secret, item->secret_len, item->content_type)) < 0)
                return sd_bus_reply_method_errorf(call, SD_BUS_ERROR_FAILED, "%s", strerror(-r));
        return sd_bus_send(NULL, reply, NULL);
}

static int reply_gate_error(sd_bus_message *call, GateResult g) {
        switch (g) {
        case GATE_CALLER:
                return sd_bus_reply_method_errorf(call, SD_BUS_ERROR_ACCESS_DENIED,
                                                  "Caller identity is too weak for this item");
        case GATE_TRUSTD:
                return sd_bus_reply_method_errorf(call, "org.freedesktop.Secret.Error.IsLocked",
                                                  "The required platform policy is not satisfied");
        case GATE_SESSION:
                return sd_bus_reply_method_errorf(call, "org.freedesktop.Secret.Error.IsLocked",
                                                  "No eligible login session is available");
        case GATE_POLICY:
                return sd_bus_reply_method_errorf(call, SD_BUS_ERROR_ACCESS_DENIED,
                                                  "The item has an unsupported release policy");
        default:
                return sd_bus_reply_method_errorf(call, "org.freedesktop.Secret.Error.IsLocked",
                                                  "The collection is locked");
        }
}

static GateResult stepup_revalidate_context(StepUp *su) {
        Manager *mgr = manager_instance;
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *system_bus = NULL;
        uid_t uid;

        if (collection_locked(mgr))
                return GATE_LOCKED;
        if (!message_session(su->call, su->xport_session, &error))
                return GATE_SESSION;
        if (sd_bus_get_name_creds(mgr->bus, su->owner, SD_BUS_CREDS_EUID, &creds) < 0 ||
            sd_bus_creds_get_euid(creds, &uid) < 0 ||
            uid != su->uid)
                return GATE_SESSION;

#ifndef SECRETD_TESTING
        if (sd_bus_open_system(&system_bus) < 0)
                return GATE_SESSION;
        (void) sd_bus_set_method_call_timeout(system_bus, 2U * 1000000U);
#endif
        if (session_eligible(system_bus, su->session, su->uid) <= 0)
                return GATE_SESSION;
        return GATE_ALLOW;
}

static GateResult stepup_revalidate(StepUp *su, Item **ret_item) {
        Item *item;
        const char *policy;
        GateResult gate;

        gate = stepup_revalidate_context(su);
        if (gate != GATE_ALLOW)
                return gate;
        item = manager_find_by_path(manager_instance, su->item_path);
        if (!item)
                return GATE_POLICY;
        gate = trust_gate_local(item, su->grade);
        if (gate != GATE_ALLOW)
                return gate;
        policy = attr_get(item->attrs, "platformd.policy");
        if (!policy || !streq(policy, su->item_policy))
                return GATE_POLICY;
        if (ret_item)
                *ret_item = item;
        return GATE_ALLOW;
}

static void stepup_fail(StepUp *su, GateResult gate) {
        (void) reply_gate_error(su->call, gate);
        stepup_free(su);
}

static bool stepup_bulk_policy_allowed(StepUp *su, const char *policy) {
        for (size_t i = 0; i < su->n_bulk_policies; i++)
                if (su->bulk_allowed[i] &&
                    streq(su->bulk_trust_policies[i], policy))
                        return true;
        return false;
}

static int stepup_send_bulk_reply(StepUp *su) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Session *session;
        int r;

        if (!(session = message_session(su->call, su->xport_session, &error)))
                return sd_bus_reply_method_error(su->call, &error);
        if ((r = sd_bus_message_new_method_return(su->call, &reply)) < 0 ||
            (r = sd_bus_message_open_container(reply, 'a', "{o(oayays)}")) < 0)
                return r;

        for (size_t i = 0; i < su->n_bulk_paths; i++) {
                Item *item = manager_find_by_path(manager_instance, su->bulk_paths[i]);
                const char *item_policy, *policy, *snapshot;

                if (!item ||
                    !su->bulk_items_present[i] ||
                    trust_gate_local(item, su->grade) != GATE_ALLOW)
                        continue;
                snapshot = su->bulk_item_policy_snapshots[i];
                item_policy = attr_get(item->attrs, "platformd.policy");
                if ((!item_policy && *snapshot) ||
                    (item_policy && (!*snapshot || !streq(item_policy, snapshot))))
                        continue;
                policy = trust_policy_name(item_policy);
                if (item_policy &&
                    (!policy || !stepup_bulk_policy_allowed(su, policy)))
                        continue;
                if ((r = sd_bus_message_open_container(reply, 'e', "o(oayays)")) < 0 ||
                    (r = sd_bus_message_append(reply, "o", item->path)) < 0 ||
                    (r = append_secret(
                                     reply,
                                     session,
                                     item->secret,
                                     item->secret_len,
                                     item->content_type)) < 0 ||
                    (r = sd_bus_message_close_container(reply)) < 0)
                        return r;
        }
        if ((r = sd_bus_message_close_container(reply)) < 0)
                return r;
        return sd_bus_send(NULL, reply, NULL);
}

static void stepup_finish_bulk(StepUp *su) {
        GateResult gate = stepup_revalidate_context(su);

        if (gate == GATE_ALLOW)
                (void) stepup_send_bulk_reply(su);
        else
                (void) reply_gate_error(su->call, gate);
        stepup_free(su);
}

static void stepup_release(StepUp *su) {
        GateResult gate = stepup_revalidate(su, NULL);

        if (gate == GATE_ALLOW)
                (void) send_item_secret(su->call, su->item_path, su->xport_session);
        else
                (void) reply_gate_error(su->call, gate);
        stepup_free(su);
}

static int stepup_call_trustd(StepUp *su);
static int stepup_call_verifyd(StepUp *su);

static int stepup_select_bulk_policy(StepUp *su) {
        size_t i = su->bulk_policy_index;

        free(su->item_path);
        free(su->item_policy);
        free(su->trust_policy);
        su->item_path = strdup(su->bulk_item_paths[i]);
        su->item_policy = strdup(su->bulk_item_policies[i]);
        su->trust_policy = strdup(su->bulk_trust_policies[i]);
        if (!su->item_path || !su->item_policy || !su->trust_policy)
                return -ENOMEM;
        su->phase = STEPUP_POLICY;
        su->grace_attempts = 0;
        return 0;
}

static void stepup_policy_done(StepUp *su, bool allowed) {
        if (!su->bulk) {
                if (allowed)
                        stepup_release(su);
                else
                        stepup_fail(su, GATE_TRUSTD);
                return;
        }

        su->bulk_allowed[su->bulk_policy_index] = allowed;
        su->bulk_policy_index++;
        if (su->bulk_policy_index >= su->n_bulk_policies) {
                stepup_finish_bulk(su);
                return;
        }
        if (stepup_select_bulk_policy(su) < 0 ||
            stepup_call_trustd(su) < 0)
                stepup_policy_done(su, false);
}

static int stepup_retry(sd_event_source *source, uint64_t usec, void *userdata) {
        StepUp *su = userdata;
        GateResult gate;

        su->retry = sd_event_source_unref(su->retry);
        gate = stepup_revalidate(su, NULL);
        if (gate != GATE_ALLOW)
                stepup_fail(su, gate);
        else if (stepup_call_trustd(su) < 0)
                stepup_policy_done(su, false);
        return 0;
}

static int stepup_schedule_retry(StepUp *su) {
        return sd_event_add_time_relative(
                        sd_bus_get_event(manager_instance->bus),
                        &su->retry,
                        CLOCK_MONOTONIC,
                        100U * 1000U,
                        10U * 1000U,
                        stepup_retry,
                        su);
}

static int trust_reply_parse(
                StepUp *su,
                sd_json_variant *parameters,
                bool *ret_satisfied,
                bool *ret_repairable) {

        sd_json_variant *result, *policy, *session, *value, *code, *reason, *window;
        const char *result_value, *reason_code, *reason_text;

        if (!parameters)
                return -EBADMSG;
        result = sd_json_variant_by_key(parameters, "result");
        policy = result ? sd_json_variant_by_key(result, "policyId") : NULL;
        session = result ? sd_json_variant_by_key(result, "sessionId") : NULL;
        value = result ? sd_json_variant_by_key(result, "result") : NULL;
        code = result ? sd_json_variant_by_key(result, "reasonCode") : NULL;
        reason = result ? sd_json_variant_by_key(result, "reason") : NULL;
        window = result ? sd_json_variant_by_key(result, "windowSec") : NULL;
        if (!policy || !session || !value || !code || !reason || !window ||
            !sd_json_variant_is_string(policy) ||
            !sd_json_variant_is_string(session) ||
            !sd_json_variant_is_string(value) ||
            !sd_json_variant_is_string(code) ||
            !sd_json_variant_is_string(reason) ||
            !sd_json_variant_is_unsigned(window) ||
            !streq(sd_json_variant_string(policy), su->trust_policy) ||
            !streq(sd_json_variant_string(session), su->session))
                return -EBADMSG;

        result_value = sd_json_variant_string(value);
        reason_code = sd_json_variant_string(code);
        reason_text = sd_json_variant_string(reason);
        if (!text_valid(reason_code, 64) || !text_valid(reason_text, 512))
                return -EBADMSG;
        if (streq(result_value, "policy-satisfied")) {
                if ((streq(su->trust_policy, "fresh-user-verification") &&
                     !streq(reason_code, "verification-fresh")) ||
                    (streq(su->trust_policy, "local-trusted-session") &&
                     !streq(reason_code, "local-trusted-session")))
                        return -EBADMSG;
                *ret_satisfied = true;
                *ret_repairable = false;
                return 0;
        }
        if (!streq(result_value, "denied"))
                return -EBADMSG;
        *ret_satisfied = false;
        *ret_repairable =
                streq(reason_code, "verification-missing") ||
                streq(reason_code, "verification-stale");
        return 0;
}

static int on_trustd_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        StepUp *su = userdata;
        bool repairable = false, satisfied = false;
        GateResult gate;

        su->vl = sd_varlink_unref(su->vl);
        gate = stepup_revalidate(su, NULL);
        if (gate != GATE_ALLOW) {
                stepup_fail(su, gate);
                return 0;
        }
        if (error_id ||
            trust_reply_parse(su, parameters, &satisfied, &repairable) < 0) {
                stepup_policy_done(su, false);
                return 0;
        }
        if (satisfied) {
                stepup_policy_done(su, true);
                return 0;
        }
        if (!repairable) {
                stepup_policy_done(su, false);
                return 0;
        }
        if (su->phase == STEPUP_POLICY) {
                su->phase = STEPUP_VERIFY;
                if (stepup_call_verifyd(su) < 0)
                        stepup_policy_done(su, false);
                return 0;
        }
        if (su->phase == STEPUP_POLICY_AFTER_VERIFY &&
            su->grace_attempts++ < 20 &&
            stepup_schedule_retry(su) >= 0)
                return 0;

        stepup_policy_done(su, false);
        return 0;
}

static int on_verifyd_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        StepUp *su = userdata;
        sd_json_variant *verified, *method, *realtime;
        GateResult gate;

        su->vl = sd_varlink_unref(su->vl);
        gate = stepup_revalidate(su, NULL);
        if (gate != GATE_ALLOW) {
                stepup_fail(su, gate);
                return 0;
        }
        verified = parameters ? sd_json_variant_by_key(parameters, "verified") : NULL;
        method = parameters ? sd_json_variant_by_key(parameters, "method") : NULL;
        realtime = parameters ? sd_json_variant_by_key(parameters, "realtimeUSec") : NULL;
        if (error_id || !verified || !sd_json_variant_is_boolean(verified) ||
            !sd_json_variant_boolean(verified) ||
            !method || !sd_json_variant_is_string(method) ||
            !streq(sd_json_variant_string(method), "platformd-verify") ||
            !realtime || !sd_json_variant_is_unsigned(realtime) ||
            sd_json_variant_unsigned(realtime) == 0) {
                stepup_policy_done(su, false);
                return 0;
        }

        su->phase = STEPUP_POLICY_AFTER_VERIFY;
        su->grace_attempts = 0;
        if (stepup_call_trustd(su) < 0)
                stepup_policy_done(su, false);
        return 0;
}

static int stepup_call_trustd(StepUp *su) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        const char *socket = getenv("PLATFORMD_TRUST_SOCKET");
        int r;

        su->vl = sd_varlink_unref(su->vl);
        r = sd_varlink_connect_address(
                        &su->vl,
                        socket && *socket ? socket :
                        "/run/platformd-trustd/io.platformd.Trust");
        if (r < 0)
                return r;
        (void) sd_varlink_set_userdata(su->vl, su);
        (void) sd_varlink_set_relative_timeout(su->vl, 2U * 1000000U);
        if ((r = sd_varlink_attach_event(
                             su->vl,
                             sd_bus_get_event(manager_instance->bus),
                             SD_EVENT_PRIORITY_NORMAL)) < 0 ||
            (r = sd_varlink_bind_reply(su->vl, on_trustd_reply)) < 0 ||
            (r = sd_json_buildo(
                             &parameters,
                             SD_JSON_BUILD_PAIR(
                                             "policy",
                                             SD_JSON_BUILD_STRING(su->trust_policy)),
                             SD_JSON_BUILD_PAIR(
                                             "sessionId",
                                             SD_JSON_BUILD_STRING(su->session)))) < 0 ||
            (r = sd_varlink_invoke(
                             su->vl,
                             "io.platformd.Trust.EvaluatePolicy",
                             parameters)) < 0)
                return r;
        return 0;
}

static int stepup_call_verifyd(StepUp *su) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        const char *socket = getenv("PLATFORMD_VERIFY_SOCKET");
        const char *reason;
        int r;

        su->vl = sd_varlink_unref(su->vl);
        r = sd_varlink_connect_address(
                        &su->vl,
                        socket && *socket ? socket :
                        "/run/platformd-verifyd/io.platformd.Verify");
        if (r < 0)
                return r;
        reason = streq(su->item_policy, "fresh-verification")
                ? "release a fresh-verification secret"
                : "release a trusted-platform secret";
        (void) sd_varlink_set_userdata(su->vl, su);
        (void) sd_varlink_set_relative_timeout(su->vl, 125U * 1000000U);
        if ((r = sd_varlink_attach_event(
                             su->vl,
                             sd_bus_get_event(manager_instance->bus),
                             SD_EVENT_PRIORITY_NORMAL)) < 0 ||
            (r = sd_varlink_bind_reply(su->vl, on_verifyd_reply)) < 0 ||
            (r = sd_json_buildo(
                             &parameters,
                             SD_JSON_BUILD_PAIR(
                                             "sessionId",
                                             SD_JSON_BUILD_STRING(su->session)),
                             SD_JSON_BUILD_PAIR(
                                             "reason",
                                             SD_JSON_BUILD_STRING(reason)))) < 0 ||
            (r = sd_varlink_invoke(
                             su->vl,
                             "io.platformd.Verify.VerifyUser",
                             parameters)) < 0)
                return r;
        return 0;
}

static int stepup_deadline(sd_event_source *source, uint64_t usec, void *userdata) {
        StepUp *su = userdata;

        su->deadline = sd_event_source_unref(su->deadline);
        if (su->bulk)
                stepup_finish_bulk(su);
        else
                stepup_fail(su, GATE_TRUSTD);
        return 0;
}

static int stepup_begin(
                sd_bus_message *message,
                const char *xport_session,
                Item *item,
                CallerGrade grade,
                sd_bus_error *error) {

        Manager *mgr = manager_instance;
        _cleanup_(sd_bus_error_free) sd_bus_error session_error = SD_BUS_ERROR_NULL;
        const char *owner = sd_bus_message_get_sender(message);
        const char *item_policy = attr_get(item->attrs, "platformd.policy");
        StepUp *su;
        int r;

        if (!message_session(message, xport_session, &session_error))
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED,
                                        "The transport session does not belong to the caller");
        if (!owner || !item_policy || !trust_policy_name(item_policy))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                        "The item has an unsupported release policy");

        su = calloc(1, sizeof *su);
        if (!su)
                return -ENOMEM;
        su->call = sd_bus_message_ref(message);
        su->owner = strdup(owner);
        su->item_path = strdup(item->path);
        su->xport_session = strdup(xport_session);
        su->item_policy = strdup(item_policy);
        su->trust_policy = strdup(trust_policy_name(item_policy));
        su->grade = grade;
        su->phase = STEPUP_POLICY;
        if (!su->call || !su->owner || !su->item_path || !su->xport_session ||
            !su->item_policy || !su->trust_policy ||
            (r = caller_session(message, &su->session, &su->uid)) < 0) {
                stepup_free(su);
                return sd_bus_error_set(error, "org.freedesktop.Secret.Error.IsLocked",
                                        "No eligible login session is available");
        }

        su->next = mgr->stepups;
        mgr->stepups = su;
        if ((r = sd_event_add_time_relative(
                             sd_bus_get_event(mgr->bus),
                             &su->deadline,
                             CLOCK_MONOTONIC,
                             130U * 1000000U,
                             100U * 1000U,
                             stepup_deadline,
                             su)) < 0 ||
            (r = stepup_call_trustd(su)) < 0) {
                stepup_free(su);
                return sd_bus_error_set(error, "org.freedesktop.Secret.Error.IsLocked",
                                        "The required platform policy is unavailable");
        }
        return 1;
}

static int stepup_begin_bulk(
                sd_bus_message *message,
                const char *xport_session,
                char **paths,
                size_t n_paths,
                CallerGrade grade,
                sd_bus_error *error) {

        Manager *mgr = manager_instance;
        _cleanup_(sd_bus_error_free) sd_bus_error session_error = SD_BUS_ERROR_NULL;
        const char *owner = sd_bus_message_get_sender(message);
        StepUp *su;
        int r;

        if (!message_session(message, xport_session, &session_error))
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED,
                                        "The transport session does not belong to the caller");
        if (!owner || n_paths > 4096)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                        "The bulk secret request is invalid");

        su = calloc(1, sizeof *su);
        if (!su)
                return -ENOMEM;
        su->call = sd_bus_message_ref(message);
        su->owner = strdup(owner);
        su->xport_session = strdup(xport_session);
        su->grade = grade;
        su->bulk = true;
        su->n_bulk_paths = n_paths;
        su->bulk_paths = calloc(n_paths, sizeof *su->bulk_paths);
        su->bulk_item_policy_snapshots =
                calloc(n_paths, sizeof *su->bulk_item_policy_snapshots);
        su->bulk_items_present = calloc(n_paths, sizeof *su->bulk_items_present);
        if (!su->call || !su->owner || !su->xport_session ||
            (n_paths > 0 &&
             (!su->bulk_paths ||
              !su->bulk_item_policy_snapshots ||
              !su->bulk_items_present))) {
                stepup_free(su);
                return -ENOMEM;
        }

        for (size_t i = 0; i < n_paths; i++) {
                Item *item;
                const char *item_policy, *trust_policy;
                bool known = false;

                su->bulk_paths[i] = strdup(paths[i]);
                if (!su->bulk_paths[i]) {
                        stepup_free(su);
                        return -ENOMEM;
                }
                item = manager_find_by_path(mgr, paths[i]);
                if (!item)
                        continue;
                su->bulk_items_present[i] = true;
                item_policy = attr_get(item->attrs, "platformd.policy");
                su->bulk_item_policy_snapshots[i] = strdup(item_policy ?: "");
                if (!su->bulk_item_policy_snapshots[i]) {
                        stepup_free(su);
                        return -ENOMEM;
                }
                if (trust_gate_local(item, grade) != GATE_ALLOW)
                        continue;
                trust_policy = trust_policy_name(item_policy);
                if (!trust_policy)
                        continue;
                for (size_t k = 0; k < su->n_bulk_policies; k++)
                        if (streq(su->bulk_trust_policies[k], trust_policy)) {
                                known = true;
                                break;
                        }
                if (known)
                        continue;
                if (su->n_bulk_policies >= 2) {
                        stepup_free(su);
                        return -E2BIG;
                }
                size_t k = su->n_bulk_policies++;
                su->bulk_trust_policies[k] = strdup(trust_policy);
                su->bulk_item_paths[k] = strdup(item->path);
                su->bulk_item_policies[k] = strdup(item_policy);
                if (!su->bulk_trust_policies[k] ||
                    !su->bulk_item_paths[k] ||
                    !su->bulk_item_policies[k]) {
                        stepup_free(su);
                        return -ENOMEM;
                }
        }

        if (su->n_bulk_policies == 0) {
                stepup_free(su);
                return -EINVAL;
        }
        if ((r = caller_session(message, &su->session, &su->uid)) < 0) {
                stepup_free(su);
                return sd_bus_error_set(error, "org.freedesktop.Secret.Error.IsLocked",
                                        "No eligible login session is available");
        }
        if ((r = stepup_select_bulk_policy(su)) < 0) {
                stepup_free(su);
                return r;
        }

        su->next = mgr->stepups;
        mgr->stepups = su;
        if ((r = sd_event_add_time_relative(
                             sd_bus_get_event(mgr->bus),
                             &su->deadline,
                             CLOCK_MONOTONIC,
                             130U * 1000000U,
                             100U * 1000U,
                             stepup_deadline,
                             su)) < 0) {
                stepup_free(su);
                return r;
        }
        if (stepup_call_trustd(su) < 0)
                stepup_policy_done(su, false);
        return 1;
}

static int item_get_secret(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Item *item = userdata;
        const char *session;
        CallerGrade grade;
        int r;

        if ((r = sd_bus_message_read(m, "o", &session)) < 0)
                return r;
        grade = caller_grade(m, "secret-read");

        switch (trust_gate_local(item, grade)) {
        case GATE_ALLOW:
                if (attr_get(item->attrs, "platformd.policy"))
                        return stepup_begin(m, session, item, grade, e);
                return send_item_secret(m, item->path, session);
        case GATE_CALLER:
                return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                        "Caller identity is too weak for this item");
        case GATE_POLICY:
                return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                        "The item has an unsupported release policy");
        case GATE_LOCKED:
        default:
                return sd_bus_error_set(e, "org.freedesktop.Secret.Error.IsLocked",
                                        "The collection is locked");
        }
}

static int persist_error(sd_bus_error *error, int r) {
        return sd_bus_error_setf(error, SD_BUS_ERROR_FAILED,
                                 "Failed to persist the secret store: %s", strerror(-r));
}

static int item_set_secret(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Item *item = userdata;
        const char *session, *ct;
        const void *params, *value;
        size_t plen, vlen;
        uint8_t *old_secret, *new_secret;
        char *old_content_type, *new_content_type;
        size_t old_secret_len;
        uint64_t old_modified;
        int r;

        if ((r = gate_mutation(item, m, e)) < 0)
                return r;
        r = sd_bus_message_enter_container(m, 'r', "oayays");
        if (r < 0)
                return r;
        if ((r = sd_bus_message_read(m, "o", &session)) < 0 ||
            (r = sd_bus_message_read_array(m, 'y', &params, &plen)) < 0 ||
            (r = sd_bus_message_read_array(m, 'y', &value, &vlen)) < 0 ||
            (r = sd_bus_message_read(m, "s", &ct)) < 0)
                return r;
        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        Session *sess = message_session(m, session, e);
        _cleanup_free_ uint8_t *dec = NULL;
        const uint8_t *store = value;
        size_t store_len = vlen;
        if (!sess)
                return -EACCES;
        if (sess->encrypted) {   /* DH session: value is AES-128-CBC, IV in parameters */
                if (plen != VAULT_DH_IV_LEN ||
                    vault_transport_decrypt(sess->aes_key, params, value, vlen, &dec, &store_len) < 0)
                        return sd_bus_error_set(e, SD_BUS_ERROR_INVALID_ARGS,
                                                "cannot decrypt the supplied secret");
                store = dec;
        }

        new_secret = memdup(store, store_len);
        if (dec)
                vault_wipe(dec, store_len);
        new_content_type = strdup((ct && *ct) ? ct : "text/plain");
        if (!new_secret || !new_content_type) {
                free(new_secret);
                free(new_content_type);
                return -ENOMEM;
        }

        old_secret = item->secret;
        old_secret_len = item->secret_len;
        old_content_type = item->content_type;
        old_modified = item->modified;
        item->secret = new_secret;
        item->secret_len = store_len;
        item->content_type = new_content_type;
        item->modified = now_secs();
        if ((r = manager_save()) < 0) {
                item->secret = old_secret;
                item->secret_len = old_secret_len;
                item->content_type = old_content_type;
                item->modified = old_modified;
                vault_wipe(new_secret, store_len);
                free(new_secret);
                free(new_content_type);
                return persist_error(e, r);
        }

        if (old_secret)
                vault_wipe(old_secret, old_secret_len);
        free(old_secret);
        free(old_content_type);
        emit_item_signal(item->collection, "ItemChanged", item->path, false);
        return sd_bus_reply_method_return(m, NULL);
}

static int item_delete(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Item *item = userdata;
        int r;

        if ((r = gate_mutation(item, m, e)) < 0)
                return r;
        /* Tombstone: drop from searches/secrets but keep the object valid. */
        item->deleted = true;
        if ((r = manager_save()) < 0) {
                item->deleted = false;
                return persist_error(e, r);
        }
        if (item->secret)
                vault_wipe(item->secret, item->secret_len);
        free(item->secret);
        item->secret = NULL;
        item->secret_len = 0;
        emit_item_signal(item->collection, "ItemDeleted", item->path, true);
        return sd_bus_reply_method_return(m, "o", "/");
}

static int item_get_locked(sd_bus *b, const char *p, const char *i, const char *prop,
                           sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        return sd_bus_message_append(reply, "b", manager_instance && collection_locked(manager_instance));
}

static int item_get_attributes(sd_bus *b, const char *p, const char *i, const char *prop,
                               sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        return append_attrs(reply, ((Item *) userdata)->attrs);
}

static int item_get_label(sd_bus *b, const char *p, const char *i, const char *prop,
                          sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        Item *item = userdata;
        return sd_bus_message_append(reply, "s", item->label ? item->label : "");
}

static int item_get_created(sd_bus *b, const char *p, const char *i, const char *prop,
                            sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        return sd_bus_message_append(reply, "t", ((Item *) userdata)->created);
}

static int item_get_modified(sd_bus *b, const char *p, const char *i, const char *prop,
                             sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        return sd_bus_message_append(reply, "t", ((Item *) userdata)->modified);
}

static int item_set_label(sd_bus *bus, const char *path, const char *interface, const char *property,
                          sd_bus_message *value, void *userdata, sd_bus_error *ret_error) {
        Item *item = userdata;
        _cleanup_free_ char *new_label = NULL;
        char *old_label;
        uint64_t old_modified;
        const char *l;
        int r = sd_bus_message_read(value, "s", &l);
        if (r < 0)
                return r;
        if (!(new_label = strdup(l ? l : "")))
                return -ENOMEM;

        old_label = item->label;
        old_modified = item->modified;
        item->label = new_label;
        item->modified = now_secs();
        if ((r = manager_save()) < 0) {
                item->label = old_label;
                item->modified = old_modified;
                return persist_error(ret_error, r);
        }

        new_label = NULL;
        free(old_label);
        (void) sd_bus_emit_properties_changed(bus, path, interface, "Modified", NULL);
        emit_item_signal(item->collection, "ItemChanged", item->path, false);
        return 1;
}

static int item_set_attributes(sd_bus *bus, const char *path, const char *interface, const char *property,
                               sd_bus_message *value, void *userdata, sd_bus_error *ret_error) {
        Item *item = userdata;
        Attr *attrs = NULL;
        Attr *old_attrs;
        uint64_t old_modified;
        int r;

        /* Attributes carry the release policy, so rewriting them is the mutation
         * that matters most because it is how a policy would be stripped. */
        if ((r = gate_mutation(item, value, ret_error)) < 0)
                return r;
        r = read_attrs(value, &attrs);
        if (r < 0)
                return r;
        if ((r = validate_platformd_attrs(attrs, ret_error)) < 0) {
                free_attrs(attrs);
                return r;
        }

        old_attrs = item->attrs;
        old_modified = item->modified;
        item->attrs = attrs;
        item->modified = now_secs();
        if ((r = manager_save()) < 0) {
                item->attrs = old_attrs;
                item->modified = old_modified;
                free_attrs(attrs);
                return persist_error(ret_error, r);
        }

        free_attrs(old_attrs);
        (void) sd_bus_emit_properties_changed(bus, path, interface, "Modified", NULL);
        emit_item_signal(item->collection, "ItemChanged", item->path, false);
        return 1;
}

static const sd_bus_vtable item_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("GetSecret", "o", "(oayays)", item_get_secret, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetSecret", "(oayays)", NULL, item_set_secret, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Delete", NULL, "o", item_delete, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("Locked", "b", item_get_locked, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_WRITABLE_PROPERTY("Attributes", "a{ss}", item_get_attributes, item_set_attributes, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_WRITABLE_PROPERTY("Label", "s", item_get_label, item_set_label, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Created", "t", item_get_created, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Modified", "t", item_get_modified, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_VTABLE_END
};

static void item_destroy(Manager *manager, Item *item) {
        if (!item)
                return;

        for (Item **p = &manager->items; *p; p = &(*p)->next)
                if (*p == item) {
                        *p = item->next;
                        break;
                }

        sd_bus_slot_unref(item->slot);
        free_attrs(item->attrs);
        if (item->secret)
                vault_wipe(item->secret, item->secret_len);
        free(item->secret);
        free(item->content_type);
        free(item->collection);
        free(item->label);
        free(item->path);
        free(item);
}

static int manager_register_item(Manager *mgr, Item *item) {
        int r;
        if (asprintf(&item->path, "%s/%" PRIu64,
                     item->collection ? item->collection : COLLECTION_PATH, ++mgr->item_seq) < 0)
                return -ENOMEM;
        r = sd_bus_add_object_vtable(mgr->bus, &item->slot, item->path,
                                     "org.freedesktop.Secret.Item", item_vtable, item);
        if (r < 0)
                return r;
        item->next = mgr->items;
        mgr->items = item;
        return 0;
}

/* --- persistence -----------------------------------------------------------
 *
 * A versioned file under $XDG_DATA_HOME/platformd-secretd/secrets (0600), in
 * host byte order (it is a local cache):
 *
 *   magic "PLTFSECR" | u32 version | u32 cipher | u32 payload_len | payload
 *
 * cipher 0 means the payload is stored in the clear; cipher 1 means the vault.c
 * AEAD wrapper has sealed it (nonce + tag precede the ciphertext). The payload is:
 *
 *   u32 item_count, then per item:
 *     u64 created, u64 modified, str content_type, str label, bytes secret,
 *     u32 attr_count, { str key, str val } per attribute
 *
 * (str/bytes are u32-length-prefixed.)
 */

#define STORE_MAX_BYTES (64u * 1024 * 1024)

typedef struct Buf { uint8_t *data; size_t len, cap; } Buf;

static int buf_append(Buf *b, const void *p, size_t n) {
        if (n > STORE_MAX_BYTES || b->len > STORE_MAX_BYTES - n)
                return -EFBIG;
        if (n == 0)
                return 0;
        if (b->len + n > b->cap) {
                size_t nc = b->cap ? b->cap : 256;
                while (nc < b->len + n) {
                        if (nc > STORE_MAX_BYTES / 2) {
                                nc = STORE_MAX_BYTES;
                                break;
                        }
                        nc *= 2;
                }
                uint8_t *d = realloc(b->data, nc);
                if (!d)
                        return -ENOMEM;
                b->data = d;
                b->cap = nc;
        }
        memcpy(b->data + b->len, p, n);
        b->len += n;
        return 0;
}
static int buf_u32(Buf *b, uint32_t v) { return buf_append(b, &v, sizeof v); }
static int buf_u64(Buf *b, uint64_t v) { return buf_append(b, &v, sizeof v); }
static int buf_bytes(Buf *b, const void *p, size_t n) {
        if (n > UINT32_MAX)
                return -EFBIG;
        int r = buf_u32(b, (uint32_t) n);
        return r < 0 ? r : buf_append(b, p, n);
}
static int buf_str(Buf *b, const char *s) { return buf_bytes(b, s ? s : "", s ? strlen(s) : 0); }

typedef struct Rd { const uint8_t *data; size_t len, pos; } Rd;

static int rd_raw(Rd *r, void *out, size_t n) {
        if (r->pos + n > r->len)
                return -EBADMSG;
        memcpy(out, r->data + r->pos, n);
        r->pos += n;
        return 0;
}
static int rd_u32(Rd *r, uint32_t *v) { return rd_raw(r, v, sizeof *v); }
static int rd_u64(Rd *r, uint64_t *v) { return rd_raw(r, v, sizeof *v); }
static int rd_bytes(Rd *r, uint8_t **out, size_t *n) {   /* fresh NUL-terminated alloc */
        uint32_t l;
        int e = rd_u32(r, &l);
        if (e < 0)
                return e;
        if (r->pos + l > r->len)
                return -EBADMSG;
        uint8_t *b = malloc((size_t) l + 1);
        if (!b)
                return -ENOMEM;
        memcpy(b, r->data + r->pos, l);
        b[l] = 0;
        r->pos += l;
        *out = b;
        if (n)
                *n = l;
        return 0;
}

static void mkdir_p(const char *path) {
        _cleanup_free_ char *p = strdup(path);
        if (!p)
                return;
        for (char *s = p + 1; *s; s++)
                if (*s == '/') { *s = 0; (void) mkdir(p, 0700); *s = '/'; }
        (void) mkdir(p, 0700);
}

static int store_path(char **ret) {
        const char *xdg = getenv("XDG_DATA_HOME");
        const char *home = getenv("HOME");
        _cleanup_free_ char *dir = NULL;
        int r;

        if (xdg && *xdg)
                r = asprintf(&dir, "%s/platformd-secretd", xdg);
        else if (home && *home)
                r = asprintf(&dir, "%s/.local/share/platformd-secretd", home);
        else
                return -ENOENT;
        if (r < 0)
                return -ENOMEM;
        mkdir_p(dir);
        return asprintf(ret, "%s/secrets", dir) < 0 ? -ENOMEM : 0;
}

static int write_atomic(const char *path, const uint8_t *data, size_t len, mode_t mode) {
        _cleanup_free_ char *tmp = NULL;
        int fd, r = 0;
        size_t off = 0;

        if (asprintf(&tmp, "%s.tmp.XXXXXX", path) < 0)
                return -ENOMEM;
        fd = mkostemp(tmp, O_CLOEXEC);
        if (fd < 0)
                return -errno;
        if (fchmod(fd, mode) < 0)
                r = -errno;
        while (r == 0 && off < len) {
                ssize_t w = write(fd, data + off, len - off);
                if (w < 0) { r = -errno; break; }
                if (w == 0) { r = -EIO; break; }
                off += (size_t) w;
        }
        if (r == 0 && fsync(fd) < 0)
                r = -errno;
        if (close(fd) < 0 && r == 0)
                r = -errno;
        if (r == 0 && rename(tmp, path) < 0)
                r = -errno;
        if (r < 0)
                (void) unlink(tmp);
        return r;
}

static int read_file(const char *path, uint8_t **data, size_t *len) {
        struct stat st;
        uint8_t *buf;
        size_t off = 0;
        int fd = open(path, O_RDONLY | O_CLOEXEC);

        if (fd < 0)
                return -errno;
        if (fstat(fd, &st) < 0) { int e = -errno; close(fd); return e; }
        if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
            (uintmax_t) st.st_size > STORE_MAX_BYTES) {
                (void) close(fd);
                return -EINVAL;
        }
        buf = malloc((size_t) st.st_size + 1);
        if (!buf) { close(fd); return -ENOMEM; }
        while (off < (size_t) st.st_size) {
                ssize_t rd = read(fd, buf + off, (size_t) st.st_size - off);
                if (rd < 0) {
                        int e = -errno;

                        vault_wipe(buf, off);
                        free(buf);
                        close(fd);
                        return e;
                }
                if (rd == 0)
                        break;
                off += (size_t) rd;
        }
        (void) close(fd);
        *data = buf;
        *len = off;
        return 0;
}

/* Load the vault key from a systemd credential ($CREDENTIALS_DIRECTORY/vault-key)
 * or, for development, the file named by $SECRETD_VAULT_KEY_FILE. It must be
 * exactly VAULT_KEY_LEN raw bytes. With no key the store is kept in the clear;
 * appropriate when the home is already encrypted (systemd-homed luks/fscrypt) or
 * when only file-permission privacy is wanted. The key stays mlock'd. */
static void load_vault_key(void) {
        const char *creddir = getenv("CREDENTIALS_DIRECTORY");
        const char *devfile = getenv("SECRETD_VAULT_KEY_FILE");
        _cleanup_free_ char *path = NULL;
        _cleanup_free_ uint8_t *data = NULL;
        size_t len = 0;

        if (creddir && *creddir) {
                if (asprintf(&path, "%s/vault-key", creddir) < 0)
                        return;
        } else if (devfile && *devfile) {
                if (!(path = strdup(devfile)))
                        return;
        } else
                return;   /* no key configured, store in the clear */

        if (read_file(path, &data, &len) < 0) {
                sd_journal_print(LOG_WARNING, "vault key %s unreadable; storing in the clear", path);
                return;
        }
        if (len != VAULT_KEY_LEN) {
                sd_journal_print(LOG_WARNING, "vault key must be %u raw bytes (got %zu); storing in the clear",
                                 VAULT_KEY_LEN, len);
                vault_wipe(data, len);
                return;
        }
        memcpy(g_vault_key, data, VAULT_KEY_LEN);
        vault_wipe(data, len);
        if (mlock(g_vault_key, sizeof g_vault_key) < 0)
                sd_journal_print(LOG_WARNING, "mlock of vault key failed (%s); continuing", strerror(errno));
        g_encrypting = true;
        sd_journal_print(LOG_INFO, "vault key loaded, store is encrypted (AES-256-GCM)");
}

static int manager_serialize(Manager *mgr, Buf *out) {
        uint32_t n = 0, cn = 0;
        int r;

        /* collections (the built-in default is always recreated, so skip it). */
        for (Collection *c = mgr->collections; c; c = c->next)
                if (!streq(c->path, COLLECTION_PATH))
                        cn++;
        if ((r = buf_u32(out, cn)) < 0)
                return r;
        for (Collection *c = mgr->collections; c; c = c->next) {
                if (streq(c->path, COLLECTION_PATH))
                        continue;
                if ((r = buf_str(out, c->path)) < 0 ||
                    (r = buf_str(out, c->label)) < 0 ||
                    (r = buf_u64(out, c->created)) < 0 ||
                    (r = buf_u64(out, c->modified)) < 0)
                        return r;
        }

        for (Item *i = mgr->items; i; i = i->next)
                if (!i->deleted)
                        n++;
        if ((r = buf_u32(out, n)) < 0)
                return r;
        for (Item *i = mgr->items; i; i = i->next) {
                if (i->deleted)
                        continue;
                uint32_t ac = 0;
                for (Attr *a = i->attrs; a; a = a->next)
                        ac++;
                if ((r = buf_u64(out, i->created)) < 0 ||
                    (r = buf_u64(out, i->modified)) < 0 ||
                    (r = buf_str(out, i->content_type)) < 0 ||
                    (r = buf_str(out, i->label)) < 0 ||
                    (r = buf_str(out, i->collection ? i->collection : COLLECTION_PATH)) < 0 ||
                    (r = buf_bytes(out, i->secret, i->secret_len)) < 0 ||
                    (r = buf_u32(out, ac)) < 0)
                        return r;
                for (Attr *a = i->attrs; a; a = a->next)
                        if ((r = buf_str(out, a->key)) < 0 || (r = buf_str(out, a->val)) < 0)
                                return r;
        }
        return 0;
}

static int manager_save(void) {
        Manager *mgr = manager_instance;
        _cleanup_free_ char *path = NULL;
        Buf payload = {0}, file = {0};
        uint8_t *ct = NULL;
        int r;

        if (!mgr)
                return -ENXIO;
        if ((r = store_path(&path)) < 0)
                return r;
        if (g_store_readonly) {   /* refuse to clobber an unreadable store */
                sd_journal_print(LOG_ERR,
                                 "refusing to save: the existing store could not be read");
                return -EROFS;
        }
        if ((r = manager_serialize(mgr, &payload)) < 0)
                goto out;
        if ((r = buf_append(&file, "PLTFSECR", 8)) < 0 ||
            (r = buf_u32(&file, 2)) < 0)   /* magic, version */
                goto out;

        if (g_encrypting) {
                uint8_t nonce[VAULT_NONCE_LEN], tag[VAULT_TAG_LEN];
                ct = malloc(payload.len ? payload.len : 1);
                if (!ct) {
                        r = -ENOMEM;
                        goto out;
                }
                if (vault_seal(g_vault_key, payload.data, payload.len, nonce, ct, tag) < 0) {
                        r = -EIO;
                        goto out;
                }
                if ((r = buf_u32(&file, 1)) < 0 ||                       /* cipher: aes-256-gcm */
                    (r = buf_append(&file, nonce, VAULT_NONCE_LEN)) < 0 ||
                    (r = buf_append(&file, tag, VAULT_TAG_LEN)) < 0 ||
                    (r = buf_bytes(&file, ct, payload.len)) < 0)
                        goto out;
        } else {
                if ((r = buf_u32(&file, 0)) < 0 ||                       /* cipher: none */
                    (r = buf_bytes(&file, payload.data, payload.len)) < 0)
                        goto out;
        }
        r = write_atomic(path, file.data, file.len, 0600);
out:
        if (ct) {
                vault_wipe(ct, payload.len);
                free(ct);
        }
        if (payload.data)
                vault_wipe(payload.data, payload.len);   /* held every secret in the clear */
        free(payload.data);
        if (!g_encrypting && file.data)
                vault_wipe(file.data, file.len);
        free(file.data);
        return r;
}

/* Parse a decrypted payload buffer into items, registering each. */
static int manager_deserialize_payload(Manager *mgr, const uint8_t *payload, size_t plen) {
        Rd p = { payload, plen, 0 };
        Collection *collections_before = mgr->collections;
        Item *items_before = mgr->items;
        uint32_t cn, n;
        int r;

        /* collections (v2): recreate each and register its object. */
        if ((r = rd_u32(&p, &cn)) < 0)
                goto fail;
        for (uint32_t k = 0; k < cn; k++) {
                uint8_t *cpath = NULL, *clabel = NULL;
                uint64_t created = 0, modified = 0;
                Collection *c;

                if ((r = rd_bytes(&p, &cpath, NULL)) < 0 ||
                    (r = rd_bytes(&p, &clabel, NULL)) < 0 ||
                    (r = rd_u64(&p, &created)) < 0 ||
                    (r = rd_u64(&p, &modified)) < 0) {
                        free(cpath); free(clabel);
                        goto fail;
                }
                c = collection_new(mgr, (char *) cpath, (char *) clabel);
                free(cpath); free(clabel);
                if (!c) {
                        r = -ENOMEM;
                        goto fail;
                }
                c->created = created;
                c->modified = modified;
                r = sd_bus_add_object_vtable(mgr->bus, &c->slot, c->path,
                                             "org.freedesktop.Secret.Collection", collection_vtable, c);
                if (r < 0) {
                        collection_destroy(mgr, c);
                        goto fail;
                }
        }

        if ((r = rd_u32(&p, &n)) < 0)
                goto fail;
        for (uint32_t k = 0; k < n; k++) {
                Item *it = calloc(1, sizeof *it);
                uint8_t *ct = NULL, *lbl = NULL, *coll = NULL, *val = NULL;
                size_t vl = 0;
                uint32_t ac = 0;
                Attr *tail = NULL;

                if (!it) {
                        r = -ENOMEM;
                        goto fail;
                }
                if ((r = rd_u64(&p, &it->created)) < 0 ||
                    (r = rd_u64(&p, &it->modified)) < 0 ||
                    (r = rd_bytes(&p, &ct, NULL)) < 0 ||
                    (r = rd_bytes(&p, &lbl, NULL)) < 0 ||
                    (r = rd_bytes(&p, &coll, NULL)) < 0 ||
                    (r = rd_bytes(&p, &val, &vl)) < 0 ||
                    (r = rd_u32(&p, &ac)) < 0) {
                        free(ct); free(lbl); free(coll); free(val); free(it);
                        goto fail;
                }
                it->content_type = (char *) ct;
                it->label = (char *) lbl;
                it->collection = (char *) coll;
                it->secret = val;
                it->secret_len = vl;
                for (uint32_t j = 0; j < ac; j++) {
                        uint8_t *key = NULL, *v = NULL;
                        Attr *a;
                        if ((r = rd_bytes(&p, &key, NULL)) < 0 ||
                            (r = rd_bytes(&p, &v, NULL)) < 0) {
                                free(key); free(v);
                                item_destroy(mgr, it);
                                goto fail;
                        }
                        if (!(a = calloc(1, sizeof *a))) {
                                free(key); free(v);
                                item_destroy(mgr, it);
                                r = -ENOMEM;
                                goto fail;
                        }
                        a->key = (char *) key;
                        a->val = (char *) v;
                        if (tail) tail->next = a; else it->attrs = a;
                        tail = a;
                }
                if ((r = manager_register_item(mgr, it)) < 0) {
                        item_destroy(mgr, it);
                        goto fail;
                }
        }

        if (p.pos != p.len) {
                r = -EBADMSG;
                goto fail;
        }
        return 0;

fail:
        while (mgr->items != items_before)
                item_destroy(mgr, mgr->items);
        while (mgr->collections != collections_before)
                collection_destroy(mgr, mgr->collections);
        return r;
}

static void manager_load(Manager *mgr) {
        _cleanup_free_ char *path = NULL;
        _cleanup_(sensitive_buffer_clear) SensitiveBuffer store = {};
        uint32_t version, cipher, plen;
        char magic[8];
        int e;

        if ((e = store_path(&path)) < 0) {
                sd_journal_print(LOG_ERR, "cannot determine the secret store path: %s", strerror(-e));
                g_store_readonly = true;
                return;
        }
        if ((e = read_file(path, &store.data, &store.size)) < 0) {
                if (e == -ENOENT)
                        return;   /* no store yet */
                sd_journal_print(LOG_ERR, "cannot read secret store %s: %s; writes disabled",
                                 path, strerror(-e));
                g_store_readonly = true;
                return;
        }

        Rd r = { store.data, store.size, 0 };
        if (rd_raw(&r, magic, 8) < 0 || memcmp(magic, "PLTFSECR", 8) != 0 ||
            rd_u32(&r, &version) < 0 || version != 2 ||
            rd_u32(&r, &cipher) < 0) {
                /* Serve no items from a foreign or newer on-disk version, but do not
                 * overwrite what we could not read. */
                sd_journal_print(LOG_ERR, "unrecognized store %s, writes disabled to protect it", path);
                g_store_readonly = true;
                return;
        }

        if (cipher == 0) {
                if (rd_u32(&r, &plen) < 0 || r.pos + plen != store.size) {
                        g_store_readonly = true;   /* do not overwrite malformed input */
                        return;
                }
                e = manager_deserialize_payload(mgr, store.data + r.pos, plen);
        } else if (cipher == 1) {
                uint8_t nonce[VAULT_NONCE_LEN], tag[VAULT_TAG_LEN];
                _cleanup_free_ uint8_t *pt = NULL;

                if (!g_encrypting) {
                        sd_journal_print(LOG_ERR, "store is encrypted but no vault key is loaded; "
                                         "serving empty; writes are disabled to protect it");
                        g_store_readonly = true;
                        return;
                }
                if (rd_raw(&r, nonce, sizeof nonce) < 0 || rd_raw(&r, tag, sizeof tag) < 0 ||
                    rd_u32(&r, &plen) < 0 || r.pos + plen != store.size) {
                        g_store_readonly = true;
                        return;
                }
                pt = malloc(plen ? plen : 1);
                if (!pt) {
                        g_store_readonly = true;
                        return;
                }
                if (vault_open(g_vault_key, nonce, store.data + r.pos, plen, tag, pt) < 0) {
                        sd_journal_print(LOG_ERR, "cannot decrypt store (wrong key or tampered); "
                                         "writes disabled to protect it");
                        g_store_readonly = true;
                        vault_wipe(pt, plen);
                        return;
                }
                e = manager_deserialize_payload(mgr, pt, plen);
                vault_wipe(pt, plen);
        } else {
                sd_journal_print(LOG_ERR, "unsupported store cipher %u, writes disabled to protect it", cipher);
                g_store_readonly = true;
                return;
        }

        if (e < 0) {
                sd_journal_print(LOG_ERR, "cannot parse secret store %s: %s; writes disabled",
                                 path, strerror(-e));
                g_store_readonly = true;
        }
}

/* --- the default collection (org.freedesktop.Secret.Collection) --- */

static Collection *collection_new(Manager *mgr, const char *path, const char *label) {
        Collection *c = calloc(1, sizeof *c);
        if (!c)
                return NULL;
        c->path = strdup(path);
        c->label = strdup(label ? label : "");
        c->created = c->modified = now_secs();
        if (!c->path || !c->label) {
                free(c->path); free(c->label); free(c);
                return NULL;
        }
        c->next = mgr->collections;
        mgr->collections = c;
        return c;
}

static void collection_destroy(Manager *mgr, Collection *c) {
        for (Collection **pp = &mgr->collections; *pp; pp = &(*pp)->next)
                if (*pp == c) { *pp = c->next; break; }
        (void) sd_bus_slot_unref(c->slot);
        free(c->path);
        free(c->label);
        free(c);
}

static int collection_create_item(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Collection *coll = userdata;
        Manager *mgr = manager_instance;
        _cleanup_free_ char *label = NULL;
        Attr *attrs = NULL;
        const char *session, *ct;
        const void *params, *value;
        size_t plen, vlen;
        int r, replace;
        const uint8_t *store;
        uint8_t *dec = NULL;
        size_t store_len;
        Session *sess;

        /* properties a{sv}: we care about Label (s) and Attributes (a{ss}). */
        r = sd_bus_message_enter_container(m, 'a', "{sv}");
        if (r < 0)
                return r;
        for (;;) {
                const char *prop;
                r = sd_bus_message_enter_container(m, 'e', "sv");
                if (r < 0)
                        goto fail;
                if (r == 0)
                        break;
                r = sd_bus_message_read(m, "s", &prop);
                if (r < 0)
                        goto fail;
                if (streq(prop, "org.freedesktop.Secret.Item.Label")) {
                        const char *l;
                        if ((r = sd_bus_message_enter_container(m, 'v', "s")) < 0 ||
                            (r = sd_bus_message_read(m, "s", &l)) < 0)
                                goto fail;
                        free(label);
                        label = strdup(l ? l : "");
                        sd_bus_message_exit_container(m);
                } else if (streq(prop, "org.freedesktop.Secret.Item.Attributes")) {
                        if ((r = sd_bus_message_enter_container(m, 'v', "a{ss}")) < 0)
                                goto fail;
                        free_attrs(attrs);
                        attrs = NULL;
                        if ((r = read_attrs(m, &attrs)) < 0)
                                goto fail;
                        sd_bus_message_exit_container(m);
                } else {
                        if ((r = sd_bus_message_skip(m, "v")) < 0)
                                goto fail;
                }
                if ((r = sd_bus_message_exit_container(m)) < 0)
                        goto fail;
        }
        if ((r = sd_bus_message_exit_container(m)) < 0)
                goto fail;
        if ((r = validate_platformd_attrs(attrs, e)) < 0)
                goto fail;

        /* secret (oayays) */
        if ((r = sd_bus_message_enter_container(m, 'r', "oayays")) < 0)
                goto fail;
        if ((r = sd_bus_message_read(m, "o", &session)) < 0 ||
            (r = sd_bus_message_read_array(m, 'y', &params, &plen)) < 0 ||
            (r = sd_bus_message_read_array(m, 'y', &value, &vlen)) < 0 ||
            (r = sd_bus_message_read(m, "s", &ct)) < 0)
                goto fail;
        if ((r = sd_bus_message_exit_container(m)) < 0)
                goto fail;

        /* DH session: the incoming value is AES-128-CBC, IV in parameters. */
        store = value;
        store_len = vlen;
        sess = message_session(m, session, e);
        if (!sess) {
                r = -EACCES;
                goto fail;
        }
        if (sess->encrypted) {
                if (plen != VAULT_DH_IV_LEN ||
                    vault_transport_decrypt(sess->aes_key, params, value, vlen, &dec, &store_len) < 0) {
                        r = -EINVAL;
                        goto fail;
                }
                store = dec;
        }

        if ((r = sd_bus_message_read(m, "b", &replace)) < 0)
                goto fail;

        /* replace: update an existing item with the same attribute set. */
        Item *item = NULL;
        bool created = false;
        if (replace)
                for (Item *i = mgr->items; i; i = i->next)
                        if (!i->deleted && i->collection && streq(i->collection, coll->path) &&
                            attrs_equal(i->attrs, attrs)) { item = i; break; }

        if (item) {
                Attr *old_attrs;
                uint8_t *old_secret, *new_secret;
                char *old_label, *old_content_type, *new_content_type;
                size_t old_secret_len;
                uint64_t old_modified;

                /* Replacing an existing item is a protected mutation. */
                if ((r = gate_mutation(item, m, e)) < 0)
                        goto fail;

                if (!label && !(label = strdup(""))) {
                        r = -ENOMEM;
                        goto fail;
                }
                new_secret = memdup(store, store_len);
                new_content_type = strdup((ct && *ct) ? ct : "text/plain");
                if (!new_secret || !new_content_type) {
                        free(new_secret);
                        free(new_content_type);
                        r = -ENOMEM;
                        goto fail;
                }

                old_attrs = item->attrs;
                old_label = item->label;
                old_secret = item->secret;
                old_secret_len = item->secret_len;
                old_content_type = item->content_type;
                old_modified = item->modified;
                item->attrs = attrs;
                attrs = NULL;
                item->label = label;
                label = NULL;
                item->secret = new_secret;
                item->secret_len = store_len;
                item->content_type = new_content_type;
                item->modified = now_secs();

                if ((r = manager_save()) < 0) {
                        Attr *failed_attrs = item->attrs;
                        char *failed_label = item->label;

                        item->attrs = old_attrs;
                        item->label = old_label;
                        item->secret = old_secret;
                        item->secret_len = old_secret_len;
                        item->content_type = old_content_type;
                        item->modified = old_modified;
                        free_attrs(failed_attrs);
                        free(failed_label);
                        vault_wipe(new_secret, store_len);
                        free(new_secret);
                        free(new_content_type);
                        r = persist_error(e, r);
                        goto fail;
                }

                free_attrs(old_attrs);
                free(old_label);
                if (old_secret)
                        vault_wipe(old_secret, old_secret_len);
                free(old_secret);
                free(old_content_type);
        } else {
                item = calloc(1, sizeof *item);
                if (!item) { r = -ENOMEM; goto fail; }
                if (!label && !(label = strdup(""))) {
                        free(item);
                        r = -ENOMEM;
                        goto fail;
                }
                item->label = label; label = NULL;
                item->attrs = attrs; attrs = NULL;
                item->secret = memdup(store, store_len); item->secret_len = store_len;
                item->content_type = strdup((ct && *ct) ? ct : "text/plain");
                item->collection = strdup(coll->path);
                item->created = item->modified = now_secs();
                if (!item->secret || !item->content_type || !item->collection) {
                        item_destroy(mgr, item);
                        r = -ENOMEM;
                        goto fail;
                }
                if ((r = manager_register_item(mgr, item)) < 0) {
                        item_destroy(mgr, item);
                        goto fail;
                }
                created = true;
                if ((r = manager_save()) < 0) {
                        item_destroy(mgr, item);
                        r = persist_error(e, r);
                        goto fail;
                }
        }

        emit_item_signal(item->collection, created ? "ItemCreated" : "ItemChanged", item->path, created);
        if (dec)
                vault_wipe(dec, store_len);
        free(dec);
        return sd_bus_reply_method_return(m, "oo", item->path, "/");

fail:
        free_attrs(attrs);
        if (dec)
                vault_wipe(dec, store_len);
        free(dec);
        return r;
}

static int append_matches(sd_bus_message *reply, Manager *mgr, Attr *query, const char *collection) {
        int r = sd_bus_message_open_container(reply, 'a', "o");
        if (r < 0)
                return r;
        for (Item *i = mgr->items; i; i = i->next)
                if (!i->deleted && attrs_match(i->attrs, query) &&
                    (!collection || (i->collection && streq(i->collection, collection)))) {
                        r = sd_bus_message_append(reply, "o", i->path);
                        if (r < 0)
                                return r;
                }
        return sd_bus_message_close_container(reply);
}

static int collection_search_items(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Collection *coll = userdata;
        Manager *mgr = manager_instance;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Attr *query = NULL;
        int r;

        if ((r = read_attrs(m, &query)) < 0)
                return r;
        r = sd_bus_message_new_method_return(m, &reply);
        if (r >= 0)
                r = append_matches(reply, mgr, query, coll->path);
        free_attrs(query);
        if (r < 0)
                return r;
        return sd_bus_send(NULL, reply, NULL);
}

static int collection_delete(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Collection *coll = userdata;
        Manager *mgr = manager_instance;
        Collection **link;
        int r;

        if (streq(coll->path, COLLECTION_PATH))
                return sd_bus_error_set(e, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "The default collection cannot be deleted");
        /* Refuse collection deletion when a protected item cannot be mutated. */
        for (Item *it = mgr->items; it; it = it->next)
                if (!it->deleted && it->collection && streq(it->collection, coll->path) &&
                    (r = gate_mutation(it, m, e)) < 0)
                        return r;

        for (Item *it = mgr->items; it; it = it->next)
                if (!it->deleted && it->collection && streq(it->collection, coll->path)) {
                        it->deleted = true;
                        it->deleting = true;
                }

        for (link = &mgr->collections; *link && *link != coll; link = &(*link)->next)
                ;
        if (!*link)
                return sd_bus_error_set(e, SD_BUS_ERROR_FAILED,
                                        "The collection is no longer registered");
        *link = coll->next;

        if ((r = manager_save()) < 0) {
                coll->next = *link;
                *link = coll;
                for (Item *it = mgr->items; it; it = it->next)
                        if (it->deleting) {
                                it->deleted = false;
                                it->deleting = false;
                        }
                return persist_error(e, r);
        }

        for (Item *it = mgr->items; it; it = it->next)
                if (it->deleting) {
                        it->deleting = false;
                        if (it->secret)
                                vault_wipe(it->secret, it->secret_len);
                        free(it->secret);
                        it->secret = NULL;
                        it->secret_len = 0;
                        emit_item_signal(coll->path, "ItemDeleted", it->path, true);
                }
        (void) sd_bus_emit_signal(mgr->bus, SECRETS_PATH, "org.freedesktop.Secret.Service",
                                  "CollectionDeleted", "o", coll->path);
        (void) sd_bus_emit_properties_changed(mgr->bus, SECRETS_PATH,
                                              "org.freedesktop.Secret.Service", "Collections", NULL);
        r = sd_bus_reply_method_return(m, "o", "/");
        collection_destroy(mgr, coll);
        return r;
}

static int collection_get_items(sd_bus *b, const char *p, const char *i, const char *prop,
                                sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        Collection *coll = userdata;
        Manager *mgr = manager_instance;
        int r = sd_bus_message_open_container(reply, 'a', "o");
        if (r < 0)
                return r;
        for (Item *it = mgr->items; it; it = it->next)
                if (!it->deleted && it->collection && streq(it->collection, coll->path) &&
                    (r = sd_bus_message_append(reply, "o", it->path)) < 0)
                        return r;
        return sd_bus_message_close_container(reply);
}

static int collection_get_label(sd_bus *b, const char *p, const char *i, const char *prop,
                                sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        return sd_bus_message_append(reply, "s", ((Collection *) userdata)->label);
}

static int collection_get_locked(sd_bus *b, const char *p, const char *i, const char *prop,
                                 sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        return sd_bus_message_append(reply, "b", collection_locked(manager_instance));
}

static int collection_get_created(sd_bus *b, const char *p, const char *i, const char *prop,
                                  sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        return sd_bus_message_append(reply, "t", ((Collection *) userdata)->created);
}

static int collection_get_modified(sd_bus *b, const char *p, const char *i, const char *prop,
                                   sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        return sd_bus_message_append(reply, "t", ((Collection *) userdata)->modified);
}

static const sd_bus_vtable collection_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("CreateItem", "a{sv}(oayays)b", "oo", collection_create_item, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SearchItems", "a{ss}", "ao", collection_search_items, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Delete", NULL, "o", collection_delete, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("Items", "ao", collection_get_items, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Label", "s", collection_get_label, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Locked", "b", collection_get_locked, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Created", "t", collection_get_created, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Modified", "t", collection_get_modified, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_SIGNAL("ItemCreated", "o", 0),
        SD_BUS_SIGNAL("ItemDeleted", "o", 0),
        SD_BUS_SIGNAL("ItemChanged", "o", 0),
        SD_BUS_VTABLE_END
};

/* --- sessions (org.freedesktop.Secret.Session) --- */

static void session_free(Manager *manager, Session *session) {
        for (Session **p = &manager->sessions; *p; p = &(*p)->next)
                if (*p == session) {
                        *p = session->next;
                        break;
                }

        sd_bus_slot_unref(session->slot);
        vault_wipe(session->aes_key, sizeof session->aes_key);
        free(session->owner);
        free(session->path);
        free(session);
}

static int method_session_close(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Session *sess = userdata;
        Manager *mgr = manager_instance;
        const char *sender = sd_bus_message_get_sender(m);

        if (!sender || !streq(sender, sess->owner))
                return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                        "The session does not belong to the caller");
        session_free(mgr, sess);
        return sd_bus_reply_method_return(m, NULL);
}

static const sd_bus_vtable session_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Close", NULL, NULL, method_session_close, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

/* --- the Service (org.freedesktop.Secret.Service) --- */

static int method_open_session(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        _cleanup_free_ char *path = NULL;
        const char *algorithm;
        int r;

        _cleanup_free_ uint8_t *our_pub = NULL;
        uint8_t aes_key[VAULT_DH_KEY_LEN];
        size_t our_pub_len = 0;
        const char *sender;
        bool dh;

        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                        "Cannot determine the D-Bus caller");
        if ((r = sd_bus_message_read(m, "s", &algorithm)) < 0)
                return r;
        dh = streq(algorithm, "dh-ietf1024-sha256-aes128-cbc-pkcs7");
        if (!dh && !streq(algorithm, "plain")) {
                (void) sd_bus_message_skip(m, "v");
                return sd_bus_error_setf(e, SD_BUS_ERROR_NOT_SUPPORTED,
                                         "unsupported session algorithm '%s'", algorithm);
        }
        if (dh) {
                const void *peer;
                size_t peer_len;
                if ((r = sd_bus_message_enter_container(m, 'v', "ay")) < 0 ||
                    (r = sd_bus_message_read_array(m, 'y', &peer, &peer_len)) < 0 ||
                    (r = sd_bus_message_exit_container(m)) < 0)
                        return r;
                if (vault_dh_transport(peer, peer_len, &our_pub, &our_pub_len, aes_key) < 0)
                        return sd_bus_error_set(e, SD_BUS_ERROR_FAILED, "DH key agreement failed");
        } else if ((r = sd_bus_message_skip(m, "v")) < 0)
                return r;

        if (asprintf(&path, SECRETS_PATH "/session/%" PRIu64, ++mgr->session_seq) < 0)
                return -ENOMEM;
        Session *sess = calloc(1, sizeof *sess);
        if (!sess)
                return -ENOMEM;
        sess->path = path;
        path = NULL;   /* owned by the session now */
        sess->owner = strdup(sender);
        if (!sess->owner) {
                free(sess->path);
                free(sess);
                return -ENOMEM;
        }
        if (dh) {
                sess->encrypted = true;
                memcpy(sess->aes_key, aes_key, VAULT_DH_KEY_LEN);
                vault_wipe(aes_key, sizeof aes_key);
        }
        r = sd_bus_add_object_vtable(mgr->bus, &sess->slot, sess->path,
                                     "org.freedesktop.Secret.Session", session_vtable, sess);
        if (r < 0) {
                vault_wipe(sess->aes_key, sizeof sess->aes_key);
                free(sess->owner);
                free(sess->path);
                free(sess);
                return r;
        }
        sess->next = mgr->sessions;
        mgr->sessions = sess;

        /* Return (ay our_pub) for DH or (s "") for plain, followed by the path. */
        if (dh) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                if ((r = sd_bus_message_new_method_return(m, &reply)) < 0 ||
                    (r = sd_bus_message_open_container(reply, 'v', "ay")) < 0 ||
                    (r = sd_bus_message_append_array(reply, 'y', our_pub, our_pub_len)) < 0 ||
                    (r = sd_bus_message_close_container(reply)) < 0 ||
                    (r = sd_bus_message_append(reply, "o", sess->path)) < 0)
                        return r;
                return sd_bus_send(NULL, reply, NULL);
        }
        return sd_bus_reply_method_return(m, "vo", "s", "", sess->path);
}

static int method_create_collection(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        _cleanup_free_ char *label = NULL, *path = NULL;
        const char *alias;
        Collection *c;
        int r;

        /* properties a{sv}: we care about the Label. */
        if ((r = sd_bus_message_enter_container(m, 'a', "{sv}")) < 0)
                return r;
        while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
                const char *prop;
                if ((r = sd_bus_message_read(m, "s", &prop)) < 0)
                        return r;
                if (streq(prop, "org.freedesktop.Secret.Collection.Label")) {
                        const char *l;
                        if (sd_bus_message_enter_container(m, 'v', "s") >= 0 &&
                            sd_bus_message_read(m, "s", &l) >= 0) {
                                free(label);
                                label = strdup(l ? l : "");
                                (void) sd_bus_message_exit_container(m);
                        }
                } else if ((r = sd_bus_message_skip(m, "v")) < 0)
                        return r;
                if ((r = sd_bus_message_exit_container(m)) < 0)
                        return r;
        }
        if (r < 0 || (r = sd_bus_message_exit_container(m)) < 0 ||
            (r = sd_bus_message_read(m, "s", &alias)) < 0)
                return r;

        /* The "default" alias always maps to the built-in default collection. */
        if (alias && streq(alias, "default"))
                return sd_bus_reply_method_return(m, "oo", COLLECTION_PATH, "/");

        if (asprintf(&path, SECRETS_PATH "/collection/c%" PRIu64, ++mgr->coll_seq) < 0)
                return -ENOMEM;
        if (!(c = collection_new(mgr, path, label ? label : "")))
                return -ENOMEM;
        if ((r = sd_bus_add_object_vtable(mgr->bus, &c->slot, c->path,
                                          "org.freedesktop.Secret.Collection", collection_vtable, c)) < 0) {
                collection_destroy(mgr, c);
                return r;
        }
        if ((r = manager_save()) < 0) {
                collection_destroy(mgr, c);
                return persist_error(e, r);
        }
        (void) sd_bus_emit_signal(mgr->bus, SECRETS_PATH, "org.freedesktop.Secret.Service",
                                  "CollectionCreated", "o", c->path);
        (void) sd_bus_emit_properties_changed(mgr->bus, SECRETS_PATH,
                                              "org.freedesktop.Secret.Service", "Collections", NULL);
        return sd_bus_reply_method_return(m, "oo", c->path, "/");
}

static int method_search_items(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Attr *query = NULL;
        int r;

        if ((r = read_attrs(m, &query)) < 0)
                return r;
        r = sd_bus_message_new_method_return(m, &reply);
        if (r >= 0) {
                if (!collection_locked(mgr)) {
                        r = append_matches(reply, mgr, query, NULL);            /* unlocked */
                        if (r >= 0)
                                r = sd_bus_message_append(reply, "ao", 0);      /* locked: none */
                } else {
                        r = sd_bus_message_append(reply, "ao", 0);              /* unlocked: none */
                        if (r >= 0)
                                r = append_matches(reply, mgr, query, NULL);    /* locked */
                }
        }
        free_attrs(query);
        if (r < 0)
                return r;
        return sd_bus_send(NULL, reply, NULL);
}

/* Build the Lock/Unlock reply: echo the requested object paths as the
 * synchronously handled set (or an empty set when nothing was done), then the
 * prompt path ("/" for none). */
static int reply_lockish(sd_bus_message *m, bool echo, const char *prompt) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *p;
        int r;

        if ((r = sd_bus_message_new_method_return(m, &reply)) < 0)
                return r;
        if ((r = sd_bus_message_open_container(reply, 'a', "o")) < 0)
                return r;
        if ((r = sd_bus_message_enter_container(m, 'a', "o")) < 0)
                return r;
        while ((r = sd_bus_message_read(m, "o", &p)) > 0)
                if (echo && (r = sd_bus_message_append(reply, "o", p)) < 0)
                        return r;
        if (r < 0)
                return r;
        if ((r = sd_bus_message_exit_container(m)) < 0 ||
            (r = sd_bus_message_close_container(reply)) < 0 ||
            (r = sd_bus_message_append(reply, "o", prompt)) < 0)
                return r;
        return sd_bus_send(NULL, reply, NULL);
}

/* --- the Prompt object (org.freedesktop.Secret.Prompt) --- */

static void prompt_free(Manager *mgr, Prompt *p) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *cancel = NULL;

        if (p->auth_slot) {
                p->auth_slot = sd_bus_slot_unref(p->auth_slot);
                if (mgr->system_bus && p->cancel_id &&
                    sd_bus_message_new_method_call(
                                    mgr->system_bus,
                                    &cancel,
                                    "org.freedesktop.PolicyKit1",
                                    "/org/freedesktop/PolicyKit1/Authority",
                                    "org.freedesktop.PolicyKit1.Authority",
                                    "CancelCheckAuthorization") >= 0 &&
                    sd_bus_message_append(cancel, "s", p->cancel_id) >= 0 &&
                    sd_bus_message_set_expect_reply(cancel, 0) >= 0)
                        (void) sd_bus_send(mgr->system_bus, cancel, NULL);
        }
        for (Prompt **pp = &mgr->prompts; *pp; pp = &(*pp)->next)
                if (*pp == p) { *pp = p->next; break; }
        (void) sd_bus_slot_unref(p->slot);
        free(p->cancel_id);
        free(p->owner);
        free(p->path);
        free(p);
}

static int on_name_owner_changed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        const char *name, *old_owner, *new_owner;
        int r;

        r = sd_bus_message_read(m, "sss", &name, &old_owner, &new_owner);
        if (r < 0)
                return r;
        if (name[0] != ':' || old_owner[0] == '\0' || new_owner[0] != '\0')
                return 0;

        for (Session *session = manager->sessions, *next; session; session = next) {
                next = session->next;
                if (streq(session->owner, name))
                        session_free(manager, session);
        }
        for (Prompt *prompt = manager->prompts, *next; prompt; prompt = next) {
                next = prompt->next;
                if (streq(prompt->owner, name))
                        prompt_free(manager, prompt);
        }
        for (StepUp *stepup = manager->stepups, *next; stepup; stepup = next) {
                next = stepup->next;
                if (streq(stepup->owner, name))
                        stepup_free(stepup);
        }

        return 0;
}

/* Completed(dismissed, variant<ao> result) returns the unlocked objects. */
static void prompt_complete(Manager *mgr, Prompt *p, bool dismissed, const char *unlocked) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *sig = NULL;

        if (sd_bus_message_new_signal(mgr->bus, &sig, p->path,
                                      "org.freedesktop.Secret.Prompt", "Completed") < 0)
                return;
        if (sd_bus_message_append(sig, "b", dismissed) < 0 ||
            sd_bus_message_open_container(sig, 'v', "ao") < 0 ||
            sd_bus_message_open_container(sig, 'a', "o") < 0 ||
            (unlocked && sd_bus_message_append(sig, "o", unlocked) < 0) ||
            sd_bus_message_close_container(sig) < 0 ||
            sd_bus_message_close_container(sig) < 0)
                return;
        (void) sd_bus_send(NULL, sig, NULL);
}

static int prompt_authorization_request(
                sd_bus_message *message,
                const char *cancel_id,
                sd_bus_message **ret) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        pid_t pid;
        uint64_t starttime;
        int r;

        if (sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds) < 0 ||
            sd_bus_creds_get_pid(creds, &pid) < 0 ||
            (starttime = proc_starttime(pid)) == 0)
                return -EACCES;
        if ((r = sd_bus_message_new_method_call(
                             manager_instance->system_bus,
                             ret,
                             "org.freedesktop.PolicyKit1",
                             "/org/freedesktop/PolicyKit1/Authority",
                             "org.freedesktop.PolicyKit1.Authority",
                             "CheckAuthorization")) < 0 ||
            (r = sd_bus_message_open_container(*ret, 'r', "sa{sv}")) < 0 ||
            (r = sd_bus_message_append(*ret, "s", "unix-process")) < 0 ||
            (r = sd_bus_message_open_container(*ret, 'a', "{sv}")) < 0 ||
            (r = sd_bus_message_append(*ret, "{sv}", "pid", "u", (uint32_t) pid)) < 0 ||
            (r = sd_bus_message_append(*ret, "{sv}", "start-time", "t", starttime)) < 0 ||
            (r = sd_bus_message_close_container(*ret)) < 0 ||
            (r = sd_bus_message_close_container(*ret)) < 0 ||
            (r = sd_bus_message_append(
                             *ret,
                             "s",
                             "io.platformd.secret1.unlock-collection")) < 0 ||
            (r = sd_bus_message_append(*ret, "a{ss}", 0)) < 0 ||
            (r = sd_bus_message_append(*ret, "us", 1U, cancel_id)) < 0)
                return r;
        return 0;
}

static int on_prompt_authorized(
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *ret_error) {

        Prompt *p = userdata;
        Manager *mgr = manager_instance;
        int authorized = 0, challenge = 0;
        bool changed = false, ok;

        p->auth_slot = sd_bus_slot_unref(p->auth_slot);
        if (!reply ||
            sd_bus_message_is_method_error(reply, NULL) ||
            sd_bus_message_enter_container(reply, 'r', "bba{ss}") < 0 ||
            sd_bus_message_read(reply, "bb", &authorized, &challenge) < 0)
                authorized = 0;

        ok = authorized && !mgr->desktop_locked;
        if (ok && mgr->manual_locked) {
                mgr->manual_locked = false;
                changed = true;
        }
        if (changed)
                emit_locked_changed();
        sd_journal_send(
                        "MESSAGE=collection unlock %s",
                        ok ? "authorized" : "declined",
                        "PRIORITY=%i",
                        LOG_NOTICE,
                        "PLATFORMD_EVENT=collection-unlock",
                        "PLATFORMD_RESULT=%s",
                        ok ? "authorized" : "declined",
                        NULL);
        prompt_complete(mgr, p, !ok, ok ? COLLECTION_PATH : NULL);
        prompt_free(mgr, p);
        return 0;
}

static int method_prompt_prompt(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Prompt *p = userdata;
        Manager *mgr = manager_instance;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL;
        const char *sender = sd_bus_message_get_sender(m);
        const char *window;
        int r;

        if (!sender || !streq(sender, p->owner))
                return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                        "The prompt does not belong to the caller");
        if ((r = sd_bus_message_read(m, "s", &window)) < 0)
                return r;
        if (!text_valid(window, 256))
                return sd_bus_error_set(e, SD_BUS_ERROR_INVALID_ARGS,
                                        "The window identifier is invalid");
        if (p->auth_slot)
                return sd_bus_error_set(e, SD_BUS_ERROR_LIMITS_EXCEEDED,
                                        "The prompt is already active");
        if (!mgr->system_bus)
                return sd_bus_error_set(e, SD_BUS_ERROR_SERVICE_UNKNOWN,
                                        "The authorization service is unavailable");

        if (mgr->desktop_locked || !mgr->manual_locked) {
                bool ok = !mgr->desktop_locked;

                prompt_complete(mgr, p, !ok, ok ? COLLECTION_PATH : NULL);
                r = sd_bus_reply_method_return(m, NULL);
                prompt_free(mgr, p);
                return r;
        }

        if ((r = prompt_authorization_request(m, p->cancel_id, &request)) < 0 ||
            (r = sd_bus_call_async(
                             mgr->system_bus,
                             &p->auth_slot,
                             request,
                             on_prompt_authorized,
                             p,
                             120U * 1000000U)) < 0)
                return sd_bus_error_set(e, SD_BUS_ERROR_FAILED,
                                        "Cannot start collection unlock authorization");
        return sd_bus_reply_method_return(m, NULL);
}

static int method_prompt_dismiss(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Prompt *p = userdata;
        Manager *mgr = manager_instance;
        const char *sender = sd_bus_message_get_sender(m);
        int r;

        if (!sender || !streq(sender, p->owner))
                return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                        "The prompt does not belong to the caller");
        if (p->auth_slot) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *cancel = NULL;

                p->auth_slot = sd_bus_slot_unref(p->auth_slot);
                if (mgr->system_bus &&
                    sd_bus_message_new_method_call(
                                    mgr->system_bus,
                                    &cancel,
                                    "org.freedesktop.PolicyKit1",
                                    "/org/freedesktop/PolicyKit1/Authority",
                                    "org.freedesktop.PolicyKit1.Authority",
                                    "CancelCheckAuthorization") >= 0 &&
                    sd_bus_message_append(cancel, "s", p->cancel_id) >= 0 &&
                    sd_bus_message_set_expect_reply(cancel, 0) >= 0)
                        (void) sd_bus_send(mgr->system_bus, cancel, NULL);
        }
        prompt_complete(mgr, p, true, NULL);
        r = sd_bus_reply_method_return(m, NULL);
        prompt_free(mgr, p);
        return r;
}

static const sd_bus_vtable prompt_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Prompt", "s", NULL, method_prompt_prompt, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Dismiss", NULL, NULL, method_prompt_dismiss, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("Completed", "bv", 0),
        SD_BUS_VTABLE_END
};

static int method_lock(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        bool was = collection_locked(mgr);

        mgr->manual_locked = true;               /* locking always succeeds */
        if (!was)
                emit_locked_changed();
        return reply_lockish(m, true, "/");
}

/* Unlock is refused while the desktop session is locked. While the desktop is
 * unlocked but an explicit Service.Lock is in effect, return a Prompt that
 * re-authenticates with polkit before clearing it. */
static int method_unlock(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        const char *sender = sd_bus_message_get_sender(m);

        if (mgr->desktop_locked)
                return reply_lockish(m, false, "/");   /* refused, no prompt */

        if (mgr->manual_locked) {
                _cleanup_free_ char *ppath = NULL;
                Prompt *p;
                int r;

                if (asprintf(&ppath, SECRETS_PATH "/prompt/%" PRIu64, ++mgr->prompt_seq) < 0)
                        return -ENOMEM;
                if (!(p = calloc(1, sizeof *p)))
                        return -ENOMEM;
                p->path = ppath;
                ppath = NULL;
                if (!sender) {
                        free(p->path);
                        free(p);
                        return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                                "Cannot determine the D-Bus caller");
                }
                p->owner = strdup(sender);
                if (asprintf(
                                    &p->cancel_id,
                                    "platformd-secretd-%u-%" PRIu64,
                                    (unsigned) getpid(),
                                    mgr->prompt_seq) < 0 ||
                    !p->owner) {
                        free(p->cancel_id);
                        free(p->path);
                        free(p);
                        return -ENOMEM;
                }
                r = sd_bus_add_object_vtable(mgr->bus, &p->slot, p->path,
                                             "org.freedesktop.Secret.Prompt", prompt_vtable, p);
                if (r < 0) {
                        free(p->cancel_id);
                        free(p->owner);
                        free(p->path);
                        free(p);
                        return r;
                }
                p->next = mgr->prompts;
                mgr->prompts = p;
                r = reply_lockish(m, false, p->path);   /* unlocked=[], prompt=path */
                if (r < 0)
                        prompt_free(mgr, p);
                return r;
        }
        return reply_lockish(m, true, "/");   /* already unlocked */
}

static int method_get_secrets(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char **paths = NULL;
        size_t n = 0;
        const char *session;
        Session *sess;
        CallerGrade grade;
        bool need_stepup = false;
        int r;

        if (collection_locked(mgr)) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *empty = NULL;
                if ((r = sd_bus_message_new_method_return(m, &empty)) < 0 ||
                    (r = sd_bus_message_open_container(empty, 'a', "{o(oayays)}")) < 0 ||
                    (r = sd_bus_message_close_container(empty)) < 0)
                        return r;
                return sd_bus_send(NULL, empty, NULL);
        }

        grade = caller_grade(m, "secret-read");

        if ((r = sd_bus_message_enter_container(m, 'a', "o")) < 0)
                return r;
        for (;;) {
                const char *p;
                r = sd_bus_message_read(m, "o", &p);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
                char **grown = reallocarray(paths, n + 1, sizeof *paths);
                if (!grown)
                        return -ENOMEM;
                paths = grown;
                paths[n++] = (char *) p;
        }
        if ((r = sd_bus_message_exit_container(m)) < 0)
                return r;
        if ((r = sd_bus_message_read(m, "o", &session)) < 0)
                return r;
        if (!(sess = message_session(m, session, e)))
                return -EACCES;

        for (size_t i = 0; i < n; i++) {
                Item *item = manager_find_by_path(mgr, paths[i]);

                if (item &&
                    trust_gate_local(item, grade) == GATE_ALLOW &&
                    trust_policy_name(attr_get(item->attrs, "platformd.policy"))) {
                        need_stepup = true;
                        break;
                }
        }
        if (need_stepup)
                return stepup_begin_bulk(m, session, paths, n, grade, e);

        if ((r = sd_bus_message_new_method_return(m, &reply)) < 0)
                return r;
        if ((r = sd_bus_message_open_container(reply, 'a', "{o(oayays)}")) < 0)
                return r;
        for (size_t k = 0; k < n; k++) {
                Item *it = manager_find_by_path(mgr, paths[k]);
                if (!it ||
                    trust_gate_local(it, grade) != GATE_ALLOW ||
                    attr_get(it->attrs, "platformd.policy"))
                        continue;
                if ((r = sd_bus_message_open_container(reply, 'e', "o(oayays)")) < 0)
                        return r;
                if ((r = sd_bus_message_append(reply, "o", it->path)) < 0)
                        return r;
                if ((r = append_secret(reply, sess, it->secret, it->secret_len, it->content_type)) < 0)
                        return r;
                if ((r = sd_bus_message_close_container(reply)) < 0)
                        return r;
        }
        if ((r = sd_bus_message_close_container(reply)) < 0)
                return r;
        return sd_bus_send(NULL, reply, NULL);
}

static int method_read_alias(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        const char *name;
        int r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
                return r;
        return sd_bus_reply_method_return(m, "o", streq(name, "default") ? COLLECTION_PATH : "/");
}

static int method_set_alias(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        int r = sd_bus_message_skip(m, "so");   /* the default alias is fixed */
        if (r < 0)
                return r;
        return sd_bus_reply_method_return(m, NULL);
}

static int property_collections(sd_bus *b, const char *p, const char *i, const char *prop,
                                sd_bus_message *reply, void *userdata, sd_bus_error *e) {
        Manager *mgr = manager_instance;
        int r = sd_bus_message_open_container(reply, 'a', "o");
        if (r < 0)
                return r;
        for (Collection *c = mgr->collections; c; c = c->next)
                if ((r = sd_bus_message_append(reply, "o", c->path)) < 0)
                        return r;
        return sd_bus_message_close_container(reply);
}

static const sd_bus_vtable service_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("OpenSession", "sv", "vo", method_open_session, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CreateCollection", "a{sv}s", "oo", method_create_collection, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SearchItems", "a{ss}", "aoao", method_search_items, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Unlock", "ao", "aoo", method_unlock, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Lock", "ao", "aoo", method_lock, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetSecrets", "aoo", "a{o(oayays)}", method_get_secrets, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReadAlias", "s", "o", method_read_alias, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetAlias", "so", NULL, method_set_alias, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("Collections", "ao", property_collections, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_SIGNAL("CollectionCreated", "o", 0),
        SD_BUS_SIGNAL("CollectionDeleted", "o", 0),
        SD_BUS_SIGNAL("CollectionChanged", "o", 0),
        SD_BUS_VTABLE_END
};

/* --- logind session-lock tracking ------------------------------------------
 *
 * The desktop's lock state drives the store's lock state: when the session
 * locks, secrets become unavailable; when it unlocks, they return. logind
 * reports this on the login1 Session object via the Lock/Unlock signals and the
 * LockedHint property.
 *
 * The signal matches are installed for all session objects and filtered against
 * mgr->my_session is the login1 path of the display session and is re-resolved
 * whenever a session appears or disappears. So tracking survives being started
 * before the session settles, and a log-out / log-in that changes the session:
 * it rebinds rather than going deaf. Best-effort: with no graphical session the
 * lock stays manual (the Lock/Unlock methods only).
 */

/* Is this the session we track? */
static bool is_my_session(Manager *mgr, sd_bus_message *m) {
        const char *path = sd_bus_message_get_path(m);
        return mgr->my_session && path && streq(mgr->my_session, path);
}

/* Re-resolve our display session's login1 object path via a dedicated (not
 * event-attached) connection, so the blocking call is safe from inside a signal
 * dispatch. Updates mgr->my_session and the initial lock state. */
static void resolve_my_session(Manager *mgr) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *session = NULL;
        const char *p;
        int locked = 0;

        free(mgr->my_session);
        mgr->my_session = NULL;

        if (sd_uid_get_display(getuid(), &session) < 0 || sd_bus_open_system(&bus) < 0)
                return;   /* no graphical session yet */
        if (sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
                               "org.freedesktop.login1.Manager", "GetSession",
                               &error, &reply, "s", session) < 0 ||
            sd_bus_message_read(reply, "o", &p) < 0 || !(mgr->my_session = strdup(p)))
                return;

        if (sd_bus_get_property_trivial(bus, "org.freedesktop.login1", mgr->my_session,
                                        "org.freedesktop.login1.Session", "LockedHint", NULL, 'b', &locked) >= 0) {
                bool was = collection_locked(mgr);
                mgr->desktop_locked = locked;
                if (was != collection_locked(mgr))
                        emit_locked_changed();
        }
}

/* Rebind when the set of sessions changes. */
static int on_sessions_changed(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        resolve_my_session(userdata);
        return 0;
}

static int on_session_lock(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        bool was = collection_locked(mgr);
        if (!is_my_session(mgr, m))
                return 0;
        mgr->desktop_locked = true;
        if (!was)
                emit_locked_changed();
        return 0;
}

static int on_session_unlock(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        bool was = collection_locked(mgr);
        if (!is_my_session(mgr, m))
                return 0;
        mgr->desktop_locked = false;
        if (was != collection_locked(mgr))
                emit_locked_changed();
        return 0;
}

static int on_session_props(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        const char *iface;

        if (!is_my_session(mgr, m))
                return 0;
        if (sd_bus_message_read(m, "s", &iface) < 0 ||
            sd_bus_message_enter_container(m, 'a', "{sv}") < 0)
                return 0;
        while (sd_bus_message_enter_container(m, 'e', "sv") > 0) {
                const char *name;
                if (sd_bus_message_read(m, "s", &name) < 0)
                        break;
                if (streq(name, "LockedHint")) {
                        int locked = 0;
                        if (sd_bus_message_enter_container(m, 'v', "b") >= 0 &&
                            sd_bus_message_read(m, "b", &locked) >= 0) {
                                (void) sd_bus_message_exit_container(m);
                                if ((bool) locked != mgr->desktop_locked) {
                                        bool was = collection_locked(mgr);
                                        mgr->desktop_locked = locked;
                                        if (was != collection_locked(mgr))
                                                emit_locked_changed();
                                }
                        }
                } else
                        (void) sd_bus_message_skip(m, "v");
                (void) sd_bus_message_exit_container(m);
        }
        (void) sd_bus_message_exit_container(m);
        return 0;
}

static void setup_logind_lock(Manager *mgr, sd_event *event) {
        if (sd_bus_open_system(&mgr->system_bus) < 0 ||
            sd_bus_attach_event(mgr->system_bus, event, SD_EVENT_PRIORITY_NORMAL) < 0) {
                mgr->system_bus = sd_bus_flush_close_unref(mgr->system_bus);
                return;   /* without the system bus only manual locking is available */
        }

        /* Match all session objects and filter to ours in the handlers; the set of
         * sessions (and which is ours) can change over the daemon's lifetime. */
        (void) sd_bus_match_signal(mgr->system_bus, NULL, "org.freedesktop.login1", NULL,
                                   "org.freedesktop.login1.Session", "Lock", on_session_lock, mgr);
        (void) sd_bus_match_signal(mgr->system_bus, NULL, "org.freedesktop.login1", NULL,
                                   "org.freedesktop.login1.Session", "Unlock", on_session_unlock, mgr);
        (void) sd_bus_match_signal(mgr->system_bus, NULL, "org.freedesktop.login1", NULL,
                                   "org.freedesktop.DBus.Properties", "PropertiesChanged", on_session_props, mgr);
        (void) sd_bus_match_signal(mgr->system_bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
                                   "org.freedesktop.login1.Manager", "SessionNew", on_sessions_changed, mgr);
        (void) sd_bus_match_signal(mgr->system_bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
                                   "org.freedesktop.login1.Manager", "SessionRemoved", on_sessions_changed, mgr);
        resolve_my_session(mgr);
        sd_journal_print(LOG_INFO, "tracking logind lock state (session %s, initial state: %s)",
                         mgr->my_session ? mgr->my_session : "none yet",
                         mgr->desktop_locked ? "locked" : "unlocked");
}

/* --- Varlink: io.platformd.Secret ------------------------------------------
 *
 * A read-only administrative surface over sd-varlink. Secret values remain on
 * the D-Bus Secret Service. The interface listens on
 * $XDG_RUNTIME_DIR/platformd-secretd/io.platformd.Secret; drive it with
 * `varlinkctl call <socket> io.platformd.Secret.GetStatus '{}'`.
 */

static int vl_get_status(sd_varlink *link, sd_json_variant *parameters,
                         sd_varlink_method_flags_t flags, void *userdata) {
        Manager *mgr = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *session = NULL;
        uint64_t count = 0;
        int r;

        for (Item *i = mgr->items; i; i = i->next)
                if (!i->deleted)
                        count++;
        (void) sd_uid_get_display(getuid(), &session);

        r = sd_json_buildo(&v,
                SD_JSON_BUILD_PAIR("locked", SD_JSON_BUILD_BOOLEAN(collection_locked(mgr))),
                SD_JSON_BUILD_PAIR("desktopLocked", SD_JSON_BUILD_BOOLEAN(mgr->desktop_locked)),
                SD_JSON_BUILD_PAIR("manualLocked", SD_JSON_BUILD_BOOLEAN(mgr->manual_locked)),
                SD_JSON_BUILD_PAIR("itemCount", SD_JSON_BUILD_UNSIGNED(count)),
                SD_JSON_BUILD_PAIR("encrypted", SD_JSON_BUILD_BOOLEAN(g_encrypting)),
                SD_JSON_BUILD_PAIR("sessionTracked", SD_JSON_BUILD_STRING(session ? session : "")),
                SD_JSON_BUILD_PAIR("homeStorage", SD_JSON_BUILD_STRING(mgr->home_storage ? mgr->home_storage : "")));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, v);
}

static int vl_list_items(sd_varlink *link, sd_json_variant *parameters,
                         sd_varlink_method_flags_t flags, void *userdata) {
        Manager *mgr = manager_instance;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *items = NULL, *result = NULL;
        int r;

        for (Item *it = mgr->items; it; it = it->next) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *attrs = NULL, *obj = NULL;

                if (it->deleted)
                        continue;
                for (Attr *a = it->attrs; a; a = a->next)
                        if ((r = sd_json_variant_set_field_string(&attrs, a->key, a->val)) < 0)
                                return r;
                if (!attrs && (r = sd_json_variant_new_object(&attrs, NULL, 0)) < 0)
                        return r;

                r = sd_json_buildo(&obj,
                        SD_JSON_BUILD_PAIR("label", SD_JSON_BUILD_STRING(it->label ? it->label : "")),
                        SD_JSON_BUILD_PAIR("attributes", SD_JSON_BUILD_VARIANT(attrs)),
                        SD_JSON_BUILD_PAIR("created", SD_JSON_BUILD_UNSIGNED(it->created)),
                        SD_JSON_BUILD_PAIR("modified", SD_JSON_BUILD_UNSIGNED(it->modified)));
                if (r < 0)
                        return r;
                if ((r = sd_json_variant_append_array(&items, obj)) < 0)
                        return r;
        }

        if (!items && (r = sd_json_variant_new_array(&items, NULL, 0)) < 0)
                return r;
        r = sd_json_buildo(&result, SD_JSON_BUILD_PAIR("items", SD_JSON_BUILD_VARIANT(items)));
        if (r < 0)
                return r;
        return sd_varlink_reply(link, result);
}

static int setup_varlink(Manager *mgr, sd_event *event) {
        _cleanup_free_ char *dir = NULL, *addr = NULL;
        const char *runtime = getenv("XDG_RUNTIME_DIR");
        int r;

        if (!runtime || !*runtime)
                return 0;   /* skip the interface without a runtime directory */
        if (asprintf(&dir, "%s/platformd-secretd", runtime) < 0 ||
            (mkdir(dir, 0700), asprintf(&addr, "%s/io.platformd.Secret", dir)) < 0)
                return -ENOMEM;

        if ((r = sd_varlink_server_new(&mgr->varlink, 0)) < 0)
                return r;
        (void) sd_varlink_server_set_description(mgr->varlink, "platformd-secretd");
        if ((r = sd_varlink_server_bind_method(mgr->varlink, "io.platformd.Secret.GetStatus", vl_get_status)) < 0 ||
            (r = sd_varlink_server_bind_method(mgr->varlink, "io.platformd.Secret.ListItems", vl_list_items)) < 0)
                return r;
        (void) unlink(addr);   /* clear a stale socket from a prior run */
        if ((r = sd_varlink_server_listen_address(mgr->varlink, addr, 0600)) < 0 ||
            (r = sd_varlink_server_attach_event(mgr->varlink, event, SD_EVENT_PRIORITY_NORMAL)) < 0)
                return r;

        sd_journal_print(LOG_INFO, "Varlink: io.platformd.Secret on %s", addr);
        return 0;
}

/* Return the systemd-homed storage type for status and diagnostics. */
static char *query_home_storage(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error err = SD_BUS_ERROR_NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = NULL;
        struct passwd *pw = getpwuid(getuid());
        const char *json, *path, *storage = NULL;
        sd_json_variant *binding, *machine, *s;
        char mids[SD_ID128_STRING_MAX];
        sd_id128_t mid;
        int incomplete;

        if (!pw || sd_bus_open_system(&bus) < 0)
                return NULL;
        if (sd_bus_call_method(bus, "org.freedesktop.home1", "/org/freedesktop/home1",
                               "org.freedesktop.home1.Manager", "GetUserRecordByName",
                               &err, &reply, "s", pw->pw_name) < 0)
                return NULL;   /* not a homed user, or homed not present */
        if (sd_bus_message_read(reply, "sbo", &json, &incomplete, &path) < 0 ||
            sd_json_parse(json, 0, &record, NULL, NULL) < 0 ||
            sd_id128_get_machine(&mid) < 0)
                return NULL;
        /* homed keeps the storage backend per-machine, under binding.<machine-id> */
        sd_id128_to_string(mid, mids);
        binding = sd_json_variant_by_key(record, "binding");
        machine = binding ? sd_json_variant_by_key(binding, mids) : NULL;
        s = machine ? sd_json_variant_by_key(machine, "storage") : NULL;
        if (s && sd_json_variant_is_string(s))
                storage = sd_json_variant_string(s);
        return storage ? strdup(storage) : NULL;
}

static void manager_clear(Manager *manager) {
        while (manager->stepups)
                stepup_free(manager->stepups);
        while (manager->prompts)
                prompt_free(manager, manager->prompts);
        while (manager->sessions)
                session_free(manager, manager->sessions);
        while (manager->items)
                item_destroy(manager, manager->items);
        while (manager->collections)
                collection_destroy(manager, manager->collections);

        manager->varlink = sd_varlink_server_unref(manager->varlink);
        free(manager->home_storage);
        free(manager->my_session);
        manager->home_storage = manager->my_session = NULL;
        manager->system_bus = sd_bus_flush_close_unref(manager->system_bus);
}

int main(void) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        Manager manager = {};
        int r;

        if ((r = sd_event_default(&event)) < 0)
                return fail("sd_event_default", r);

        /* exit cleanly on SIGTERM/SIGINT (systemctl stop, Ctrl-C); NULL handler
         * = sd-event's default, which calls sd_event_exit(). */
        (void) sd_event_add_signal(event, NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, NULL, NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT | SD_EVENT_SIGNAL_PROCMASK, NULL, NULL);

        if ((r = sd_bus_open_user(&bus)) < 0)
                return fail("connect to session bus", r);

        manager.bus = bus;
        manager.coll_created = now_secs();
        manager_instance = &manager;

        Collection *defcoll = collection_new(&manager, COLLECTION_PATH, COLLECTION_LABEL);
        if (!defcoll)
                return fail("create the default collection", -ENOMEM);

        if ((r = sd_bus_add_object_vtable(bus, NULL, SECRETS_PATH,
                                          "org.freedesktop.Secret.Service", service_vtable, &manager)) < 0)
                return fail("install Service vtable", r);
        if ((r = sd_bus_add_object_vtable(bus, NULL, COLLECTION_PATH,
                                          "org.freedesktop.Secret.Collection", collection_vtable, defcoll)) < 0)
                return fail("install Collection vtable", r);
        if ((r = sd_bus_add_object_vtable(bus, NULL, ALIAS_PATH,
                                          "org.freedesktop.Secret.Collection", collection_vtable, defcoll)) < 0)
                return fail("install default-alias vtable", r);
        load_vault_key();         /* enables encryption if a vault key is configured */
        manager_load(&manager);   /* restore persisted items (registers their objects) */
        manager.home_storage = query_home_storage();
        if (!g_encrypting && manager.home_storage) {
                if (streq(manager.home_storage, "luks") || streq(manager.home_storage, "fscrypt"))
                        sd_journal_print(LOG_INFO,
                                "store kept in the clear on an encrypted home (storage=%s)",
                                manager.home_storage);
                else
                        sd_journal_print(LOG_WARNING,
                                "secrets at rest are UNENCRYPTED (homed storage=%s, no vault key); "
                                "set LoadCredentialEncrypted in the unit to protect them",
                                manager.home_storage);
        }

        if ((r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL)) < 0)
                return fail("attach bus to event loop", r);
        if ((r = sd_bus_match_signal(bus, NULL, "org.freedesktop.DBus",
                                     "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                     "NameOwnerChanged", on_name_owner_changed, &manager)) < 0)
                return fail("track D-Bus client lifetime", r);

        setup_logind_lock(&manager, event);   /* tie lock state to the desktop session */
        (void) setup_varlink(&manager, event); /* io.platformd.Secret admin interface */

        r = sd_bus_request_name(bus, SECRETS_NAME, 0);
        if (r < 0) {
                sd_journal_print(LOG_ERR, "cannot claim %s "
                                 "(another Secret Service provider already running?): %s",
                                 SECRETS_NAME, strerror(-r));
                return EXIT_FAILURE;
        }

        sd_notifyf(0, "READY=1\n"
                      "STATUS=Serving org.freedesktop.secrets (persistent store, %s)",
                   g_store_readonly ? "read-only: store unreadable" :
                   g_encrypting ? "encrypted" : "plaintext");
        sd_journal_print(LOG_INFO, "claimed %s, serving (%s store)", SECRETS_NAME,
                         g_encrypting ? "encrypted" : "plaintext");

        r = sd_event_loop(event);
        manager_clear(&manager);
        vault_wipe(g_vault_key, sizeof g_vault_key);
        manager_instance = NULL;
        if (r < 0)
                return fail("event loop", r);
        return EXIT_SUCCESS;
}
