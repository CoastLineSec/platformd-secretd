/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * platformd-secretd — platform-auth-aware Secret Service provider.
 *
 * Milestone M2: claim org.freedesktop.secrets on the session bus and serve a
 * working Secret Service over sd-bus / sd-event — a default collection, items,
 * CreateItem / GetSecret / SearchItems / GetSecrets — so `secret-tool` round
 * trips. Storage is in-memory and plaintext; encryption at rest is M3, and
 * trust-gating (lock/unlock, fresh verification) is M4. See docs/secret-service.md.
 */

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
        char *path;
        char *label;
        Attr *attrs;
        uint8_t *secret;
        size_t secret_len;
        char *content_type;
        char *collection;       /* owning collection's object path */
        uint64_t created, modified;
        bool deleted;
} Item;

typedef struct Session {
        struct Session *next;
        char *path;
        sd_bus_slot *slot;      /* the Session object's vtable, unref'd on Close */
        bool encrypted;         /* DH transport (vs plain) — reserved for DH */
        uint8_t aes_key[16];    /* AES-128 transport key when encrypted */
} Session;

typedef struct Prompt {
        struct Prompt *next;
        char *path;
        sd_bus_slot *slot;      /* the Prompt object's vtable, unref'd on completion */
} Prompt;

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
        bool desktop_locked;    /* logind session lock (LockedHint / Lock+Unlock) */
        bool manual_locked;     /* explicit Service.Lock */
        uint64_t last_verify;   /* CLOCK_MONOTONIC secs of the last unlock/verify */
        sd_bus *system_bus;     /* logind lock tracking */
        sd_varlink_server *varlink;   /* io.platformd.Secret admin interface */
        char *home_storage;           /* systemd-homed storage type, cached at startup */
        Session *sessions;
        Prompt *prompts;
        Collection *collections;
        Item *items;
} Manager;

/* Single-instance daemon: the running manager, so mutation handlers (which hold
 * only an Item*) can persist without a back-pointer. */
static Manager *manager_instance;
static void manager_save(void);
static void manager_load(Manager *mgr);
static Collection *collection_new(Manager *mgr, const char *path, const char *label);
static const sd_bus_vtable collection_vtable[];

/* The vault key (loaded from a systemd credential); g_encrypting gates sealing. */
static uint8_t g_vault_key[VAULT_KEY_LEN];
static bool g_encrypting;
static uint64_t g_fresh_window = 300;   /* seconds; fresh-verification window (0 = off) */

static int fail(const char *what, int r) {
        sd_journal_print(LOG_ERR, "%s: %s", what, strerror(-r));
        return EXIT_FAILURE;
}

static uint64_t now_secs(void) { return (uint64_t) time(NULL); }

static uint64_t now_mono(void) {   /* monotonic seconds, for freshness windows */
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t) ts.tv_sec;
}

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

static Session *find_session(Manager *m, const char *path) {
        if (m && path && *path)
                for (Session *s = m->sessions; s; s = s->next)
                        if (streq(s->path, path))
                                return s;
        return NULL;
}

/* Secret Service secret struct: (o session, ay parameters, ay value, s content-type).
 * On a DH session the value is AES-128-CBC encrypted and the IV rides in parameters. */
static int append_secret(sd_bus_message *reply, const char *session,
                         const uint8_t *value, size_t len, const char *ct) {
        Session *sess = find_session(manager_instance, session);
        _cleanup_free_ uint8_t *enc = NULL;
        const uint8_t *params = NULL, *out = value;
        size_t params_len = 0, out_len = len;
        uint8_t iv[VAULT_DH_IV_LEN];
        int r;

        if (sess && sess->encrypted) {
                if (vault_transport_encrypt(sess->aes_key, value, len, iv, &enc, &out_len) < 0)
                        return -EIO;
                out = enc;
                params = iv;
                params_len = VAULT_DH_IV_LEN;
        }
        if ((r = sd_bus_message_open_container(reply, 'r', "oayays")) < 0 ||
            (r = sd_bus_message_append(reply, "o", (session && *session) ? session : "/")) < 0 ||
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

/* --- caller identity -------------------------------------------------------
 *
 * Knowing the user is not enough; the provider must also grade "who is the
 * caller?". On Linux this is weak for same-user processes, so identity is
 * treated as graded evidence, never a binary. This records and reports the grade
 * for every secret read; enforcement is tied to item release policy (later).
 */

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

static CallerGrade caller_grade(sd_bus_message *m) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        CallerGrade grade = CALLER_UNKNOWN;
        uid_t uid = (uid_t) -1;
        pid_t pid = 0;
        const char *unit = NULL, *cgroup = NULL;

        if (sd_bus_query_sender_creds(m,
                                      SD_BUS_CREDS_UID | SD_BUS_CREDS_PID |
                                      SD_BUS_CREDS_USER_UNIT | SD_BUS_CREDS_CGROUP |
                                      SD_BUS_CREDS_AUGMENT, &creds) < 0 || !creds)
                return CALLER_UNKNOWN;

        (void) sd_bus_creds_get_uid(creds, &uid);
        (void) sd_bus_creds_get_pid(creds, &pid);
        (void) sd_bus_creds_get_user_unit(creds, &unit);
        (void) sd_bus_creds_get_cgroup(creds, &cgroup);

        if ((cgroup && strstr(cgroup, "flatpak")) || (unit && strstr(unit, "flatpak")))
                grade = CALLER_SANDBOXED_APP;   /* has a sandbox/app identity */
        else if (unit)
                grade = CALLER_SYSTEMD_UNIT;    /* belongs to a named user unit */
        else if (uid != (uid_t) -1)
                grade = CALLER_SAME_USER_WEAK;  /* ordinary same-uid process */

        sd_journal_send("MESSAGE=secret read: uid=%d pid=%d unit=%s grade=%s",
                        (int) uid, (int) pid, unit ? unit : "-", caller_grade_name(grade),
                        "PRIORITY=%i", LOG_INFO,
                        "PLATFORMD_EVENT=secret-read",
                        "PLATFORMD_CALLER_UID=%d", (int) uid,
                        "PLATFORMD_CALLER_PID=%d", (int) pid,
                        "PLATFORMD_CALLER_UNIT=%s", unit ? unit : "",
                        "PLATFORMD_CALLER_GRADE=%s", caller_grade_name(grade),
                        NULL);
        return grade;
}

static CallerGrade grade_from_name(const char *s) {
        if (streq(s, "sandboxed-app"))  return CALLER_SANDBOXED_APP;
        if (streq(s, "systemd-unit"))   return CALLER_SYSTEMD_UNIT;
        if (streq(s, "same-user-weak")) return CALLER_SAME_USER_WEAK;
        return CALLER_UNKNOWN;
}

/* --- the trust gate --------------------------------------------------------
 *
 * Decide whether this caller may read this item now, combining the collection
 * lock state, the item's opt-in release policy + freshness, and the caller's
 * identity grade. Items opt in via attributes:
 *   platformd.policy = fresh-verification   (require unlock within g_fresh_window)
 *   platformd.policy = trusted-platform     (require platformd-trustd's local-trusted-session verdict)
 *   platformd.min-grade = <grade>           (require at least this caller grade)
 * With no attributes an item is released whenever the collection is unlocked.
 */
/* Effective lock: locked if the desktop session is locked (logind) or an
 * explicit Service.Lock is in effect. */
static bool collection_locked(Manager *m) {
        return m->desktop_locked || m->manual_locked;
}

/* The caller's user's graphical (display) session — the platform-trust question
 * is about the user's desktop presence, not the specific caller process. */
static int caller_session(sd_bus_message *m, char **ret) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        uid_t uid;

        *ret = NULL;
        if (sd_bus_query_sender_creds(m, SD_BUS_CREDS_EUID | SD_BUS_CREDS_AUGMENT, &creds) < 0 ||
            sd_bus_creds_get_euid(creds, &uid) < 0)
                return -1;
        return sd_uid_get_display(uid, ret);
}

/* Consult platformd-trustd's local-trusted-session verdict over its Varlink
 * socket — a raw exchange (JSON + NUL), since sd_varlink_call re-enters the event
 * loop inside a bus handler. Returns 1 satisfied, 0 denied, -1 trustd unavailable. */
static int trustd_local_trusted(const char *session) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        sd_json_variant *params, *outer, *res;
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        struct timeval tv = { .tv_sec = 2 };
        _cleanup_free_ char *buf = NULL;
        const char *sock;
        char req[256];
        size_t buflen = 0, cap = 0;
        int fd, len;

        if (!session || !*session)
                return 0;
        sock = getenv("PLATFORMD_TRUST_SOCKET");
        if (!sock || !*sock)
                sock = "/run/platformd-trustd/io.platformd.Trust";
        strncpy(sa.sun_path, sock, sizeof sa.sun_path - 1);
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -1;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
                close(fd);
                return -1;   /* trustd not running */
        }
        len = snprintf(req, sizeof req,
                "{\"method\":\"io.platformd.Trust.EvaluatePolicy\","
                "\"parameters\":{\"policy\":\"local-trusted-session\",\"sessionId\":\"%s\"}}",
                session);
        if (len < 0 || len >= (int) sizeof req || write(fd, req, (size_t) len + 1) != (ssize_t) len + 1) {
                close(fd);
                return -1;
        }
        for (;;) {
                char chunk[1024];
                ssize_t n = read(fd, chunk, sizeof chunk);
                char *nb;

                if (n <= 0)
                        break;
                if (buflen + (size_t) n + 1 > cap) {
                        cap = (buflen + (size_t) n + 1) * 2;
                        if (!(nb = realloc(buf, cap)))
                                break;
                        buf = nb;
                }
                memcpy(buf + buflen, chunk, (size_t) n);
                buflen += (size_t) n;
                if (memchr(chunk, 0, (size_t) n))
                        break;
        }
        close(fd);
        if (!buf)
                return -1;
        buf[buflen] = 0;
        if (sd_json_parse(buf, 0, &reply, NULL, NULL) < 0 || sd_json_variant_by_key(reply, "error"))
                return -1;
        params = sd_json_variant_by_key(reply, "parameters");
        outer = params ? sd_json_variant_by_key(params, "result") : NULL;
        res = outer ? sd_json_variant_by_key(outer, "result") : NULL;
        return res && sd_json_variant_is_string(res) &&
               streq(sd_json_variant_string(res), "policy-satisfied") ? 1 : 0;
}

/* Ask platformd-verifyd to prove the caller's user is present now (it drives the
 * platformd-verify PAM stack — fingerprint, face, …). A raw exchange with a long
 * receive timeout, since the user must physically respond. Returns 1 verified,
 * 0 declined or the service is unavailable. */
static int verifyd_verify_user(const char *session, const char *reason) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        sd_json_variant *params, *verified;
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        struct timeval tv = { .tv_sec = 120 };
        _cleanup_free_ char *buf = NULL;
        const char *sock;
        char req[512];
        size_t buflen = 0, cap = 0;
        int fd, len;

        sock = getenv("PLATFORMD_VERIFY_SOCKET");
        if (!sock || !*sock)
                sock = "/run/platformd-verifyd/io.platformd.Verify";
        strncpy(sa.sun_path, sock, sizeof sa.sun_path - 1);
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return 0;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
                close(fd);
                return 0;   /* verification service not running */
        }
        len = snprintf(req, sizeof req,
                "{\"method\":\"io.platformd.Verify.VerifyUser\","
                "\"parameters\":{\"sessionId\":\"%s\",\"reason\":\"%s\"}}",
                session ?: "", reason ?: "");
        if (len < 0 || len >= (int) sizeof req || write(fd, req, (size_t) len + 1) != (ssize_t) len + 1) {
                close(fd);
                return 0;
        }
        for (;;) {
                char chunk[1024];
                ssize_t n = read(fd, chunk, sizeof chunk);
                char *nb;

                if (n <= 0)
                        break;
                if (buflen + (size_t) n + 1 > cap) {
                        cap = (buflen + (size_t) n + 1) * 2;
                        if (!(nb = realloc(buf, cap)))
                                break;
                        buf = nb;
                }
                memcpy(buf + buflen, chunk, (size_t) n);
                buflen += (size_t) n;
                if (memchr(chunk, 0, (size_t) n))
                        break;
        }
        close(fd);
        if (!buf)
                return 0;
        buf[buflen] = 0;
        if (sd_json_parse(buf, 0, &reply, NULL, NULL) < 0 || sd_json_variant_by_key(reply, "error"))
                return 0;
        params = sd_json_variant_by_key(reply, "parameters");
        verified = params ? sd_json_variant_by_key(params, "verified") : NULL;
        return verified && sd_json_variant_boolean(verified) ? 1 : 0;
}

typedef enum { GATE_ALLOW, GATE_LOCKED, GATE_STALE, GATE_CALLER, GATE_TRUSTD } GateResult;

static GateResult trust_gate(Item *item, CallerGrade grade, sd_bus_message *m) {
        Manager *mgr = manager_instance;
        const char *policy, *mingrade;

        if (collection_locked(mgr))
                return GATE_LOCKED;

        policy = attr_get(item->attrs, "platformd.policy");
        if (policy && streq(policy, "fresh-verification") && g_fresh_window > 0 &&
            now_mono() - mgr->last_verify > g_fresh_window)
                return GATE_STALE;
        if (policy && streq(policy, "trusted-platform")) {
                _cleanup_free_ char *session = NULL;
                (void) caller_session(m, &session);
                if (trustd_local_trusted(session) != 1)   /* denied or trustd absent */
                        return GATE_TRUSTD;
        }

        mingrade = attr_get(item->attrs, "platformd.min-grade");
        if (mingrade && grade < grade_from_name(mingrade))
                return GATE_CALLER;

        return GATE_ALLOW;
}

/* Interactive step-up: ask polkit (auth_self, via the desktop's agent) to
 * re-verify the user's presence for a stale fresh-verification item. Synchronous
 * — the event loop pauses during the prompt; making this async is a later
 * hardening. Returns true only if the user actually authenticated. */
/* /proc/<pid>/stat field 22 — the process start time in clock ticks, as
 * polkit's unix-process subject expects it. */
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

static bool polkit_check_fresh(sd_bus_message *m) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error err = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        int authorized = 0, challenge = 0, r;
        pid_t pid = 0;

        /* Dedicated connection: a synchronous sd_bus_call() must not run on the
         * event-loop-attached bus. Subject is the caller's process (pid +
         * start-time): polkit 127 SIGABRTs on unix-session subjects, so we
         * identify the caller by process instead of by its logind session. */
        if (sd_bus_query_sender_creds(m, SD_BUS_CREDS_PID, &creds) < 0 ||
            sd_bus_creds_get_pid(creds, &pid) < 0 ||
            sd_bus_open_system(&bus) < 0)
                return false;

        r = sd_bus_message_new_method_call(bus, &req,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization");
        if (r < 0)
                return false;
        /* subject (sa{sv}) = "unix-process", { "pid": u, "start-time": t } */
        if (sd_bus_message_open_container(req, 'r', "sa{sv}") < 0 ||
            sd_bus_message_append(req, "s", "unix-process") < 0 ||
            sd_bus_message_open_container(req, 'a', "{sv}") < 0 ||
            sd_bus_message_append(req, "{sv}", "pid", "u", (uint32_t) pid) < 0 ||
            sd_bus_message_append(req, "{sv}", "start-time", "t", proc_starttime(pid)) < 0 ||
            sd_bus_message_close_container(req) < 0 ||   /* a{sv} */
            sd_bus_message_close_container(req) < 0)     /* subject struct */
                return false;
        /* action_id, empty details, flags (1 = AllowUserInteraction), cancel id */
        if (sd_bus_message_append(req, "s", "io.platformd.secret1.verify-fresh") < 0 ||
            sd_bus_message_append(req, "a{ss}", 0) < 0 ||
            sd_bus_message_append(req, "us", 1U, "") < 0)
                return false;

        r = sd_bus_call(bus, req, 120ULL * 1000000, &err, &reply);   /* waits for the prompt */
        if (r < 0) {
                sd_journal_print(LOG_WARNING, "polkit CheckAuthorization failed: %s",
                                 err.message ? err.message : strerror(-r));
                return false;
        }
        if (sd_bus_message_enter_container(reply, 'r', "bba{ss}") < 0 ||
            sd_bus_message_read(reply, "bb", &authorized, &challenge) < 0)
                return false;

        sd_journal_send("MESSAGE=fresh-verification %s", authorized ? "granted" : "declined",
                        "PRIORITY=%i", LOG_NOTICE,
                        "PLATFORMD_EVENT=fresh-verification",
                        "PLATFORMD_RESULT=%s", authorized ? "granted" : "declined",
                        NULL);
        return authorized;
}

static int item_get_secret(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Item *item = userdata;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *session;
        int r;
        CallerGrade grade = caller_grade(m);
        GateResult g = trust_gate(item, grade, m);

        /* A stale fresh-verification item gets one chance to prove presence: a
         * polkit prompt (auth_self) via the desktop agent. On success it is fresh
         * again and released; nothing else can refresh it. */
        if (g == GATE_STALE && polkit_check_fresh(m)) {
                manager_instance->last_verify = now_mono();
                g = GATE_ALLOW;
        }

        /* A stale trusted-platform item is re-verified through platformd-verifyd:
         * it proves the user present (fingerprint, face, …) and refreshes the trust
         * authority, so if platformd-trustd then reports the platform trusted,
         * release. One call — no polkit action, no borrowed PAM module. */
        if (g == GATE_TRUSTD) {
                _cleanup_free_ char *session = NULL;
                (void) caller_session(m, &session);
                if (verifyd_verify_user(session, "release a trusted-platform secret") &&
                    trustd_local_trusted(session) == 1)
                        g = GATE_ALLOW;
        }

        switch (g) {
        case GATE_LOCKED:
                return sd_bus_error_set(e, "org.freedesktop.Secret.Error.IsLocked",
                                        "The collection is locked");
        case GATE_STALE:
                return sd_bus_error_set(e, "org.freedesktop.Secret.Error.IsLocked",
                                        "Fresh verification required (declined)");
        case GATE_CALLER:
                return sd_bus_error_set(e, SD_BUS_ERROR_ACCESS_DENIED,
                                        "Caller identity is too weak for this item");
        case GATE_TRUSTD:
                return sd_bus_error_set(e, "org.freedesktop.Secret.Error.IsLocked",
                                        "Platform is not in a trusted state (platformd-trustd)");
        case GATE_ALLOW:
                break;
        }

        r = sd_bus_message_read(m, "o", &session);
        if (r < 0)
                return r;
        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;
        r = append_secret(reply, session, item->secret, item->secret_len, item->content_type);
        if (r < 0)
                return r;
        return sd_bus_send(NULL, reply, NULL);
}

static int item_set_secret(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Item *item = userdata;
        const char *session, *ct;
        const void *params, *value;
        size_t plen, vlen;
        int r;

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

        Session *sess = find_session(manager_instance, session);
        _cleanup_free_ uint8_t *dec = NULL;
        const uint8_t *store = value;
        size_t store_len = vlen;
        if (sess && sess->encrypted) {   /* DH session: value is AES-128-CBC, IV in parameters */
                if (plen != VAULT_DH_IV_LEN ||
                    vault_transport_decrypt(sess->aes_key, params, value, vlen, &dec, &store_len) < 0)
                        return sd_bus_error_set(e, SD_BUS_ERROR_INVALID_ARGS,
                                                "cannot decrypt the supplied secret");
                store = dec;
        }

        if (item->secret)
                vault_wipe(item->secret, item->secret_len);
        free(item->secret);
        item->secret = memdup(store, store_len);
        item->secret_len = store_len;
        free(item->content_type);
        item->content_type = strdup((ct && *ct) ? ct : "text/plain");
        item->modified = now_secs();
        manager_save();
        emit_item_signal(item->collection, "ItemChanged", item->path, false);
        return sd_bus_reply_method_return(m, NULL);
}

static int item_delete(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Item *item = userdata;
        /* M2: tombstone — drop from searches/secrets but keep the object valid. */
        item->deleted = true;
        if (item->secret)
                vault_wipe(item->secret, item->secret_len);
        free(item->secret);
        item->secret = NULL;
        item->secret_len = 0;
        manager_save();
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
        const char *l;
        int r = sd_bus_message_read(value, "s", &l);
        if (r < 0)
                return r;
        free(item->label);
        item->label = strdup(l ? l : "");
        item->modified = now_secs();
        manager_save();
        (void) sd_bus_emit_properties_changed(bus, path, interface, "Modified", NULL);
        emit_item_signal(item->collection, "ItemChanged", item->path, false);
        return 1;
}

static int item_set_attributes(sd_bus *bus, const char *path, const char *interface, const char *property,
                               sd_bus_message *value, void *userdata, sd_bus_error *ret_error) {
        Item *item = userdata;
        Attr *attrs = NULL;
        int r = read_attrs(value, &attrs);
        if (r < 0)
                return r;
        free_attrs(item->attrs);
        item->attrs = attrs;
        item->modified = now_secs();
        manager_save();
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

static int manager_register_item(Manager *mgr, Item *item) {
        int r;
        if (asprintf(&item->path, "%s/%" PRIu64,
                     item->collection ? item->collection : COLLECTION_PATH, ++mgr->item_seq) < 0)
                return -ENOMEM;
        r = sd_bus_add_object_vtable(mgr->bus, NULL, item->path,
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
 * cipher 0 means the payload is stored in the clear; the vault.c AEAD wrapper
 * (M3) will set cipher 1 and seal the same payload. The payload is:
 *
 *   u32 item_count, then per item:
 *     u64 created, u64 modified, str content_type, str label, bytes secret,
 *     u32 attr_count, { str key, str val } per attribute
 *
 * (str/bytes are u32-length-prefixed.)
 */

typedef struct Buf { uint8_t *data; size_t len, cap; } Buf;

static int buf_append(Buf *b, const void *p, size_t n) {
        if (b->len + n > b->cap) {
                size_t nc = b->cap ? b->cap : 256;
                while (nc < b->len + n) nc *= 2;
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

        if (asprintf(&tmp, "%s.tmp", path) < 0)
                return -ENOMEM;
        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
        if (fd < 0)
                return -errno;
        while (off < len) {
                ssize_t w = write(fd, data + off, len - off);
                if (w < 0) { r = -errno; break; }
                off += (size_t) w;
        }
        if (r == 0 && fsync(fd) < 0)
                r = -errno;
        (void) close(fd);
        if (r == 0 && rename(tmp, path) < 0)
                r = -errno;
        if (r < 0)
                (void) unlink(tmp);
        return r;
}

#define STORE_MAX_BYTES (64u * 1024 * 1024)   /* refuse absurd store/key files */

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
                if (rd < 0) { int e = -errno; free(buf); close(fd); return e; }
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
 * exactly VAULT_KEY_LEN raw bytes. With no key the store is kept in the clear —
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
                return;   /* no key configured → store in the clear */

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
        sd_journal_print(LOG_INFO, "vault key loaded — store is encrypted (AES-256-GCM)");
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

static void manager_save(void) {
        Manager *mgr = manager_instance;
        _cleanup_free_ char *path = NULL;
        Buf payload = {0}, file = {0};
        uint8_t *ct = NULL;

        if (!mgr || store_path(&path) < 0)
                return;
        if (manager_serialize(mgr, &payload) < 0)
                goto out;
        if (buf_append(&file, "PLTFSECR", 8) < 0 || buf_u32(&file, 2) < 0)   /* magic, version */
                goto out;

        if (g_encrypting) {
                uint8_t nonce[VAULT_NONCE_LEN], tag[VAULT_TAG_LEN];
                ct = malloc(payload.len ? payload.len : 1);
                if (!ct || vault_seal(g_vault_key, payload.data, payload.len, nonce, ct, tag) < 0)
                        goto out;
                if (buf_u32(&file, 1) < 0 ||                             /* cipher: aes-256-gcm */
                    buf_append(&file, nonce, VAULT_NONCE_LEN) < 0 ||
                    buf_append(&file, tag, VAULT_TAG_LEN) < 0 ||
                    buf_bytes(&file, ct, payload.len) < 0)
                        goto out;
        } else {
                if (buf_u32(&file, 0) < 0 ||                             /* cipher: none */
                    buf_bytes(&file, payload.data, payload.len) < 0)
                        goto out;
        }
        (void) write_atomic(path, file.data, file.len, 0600);
out:
        if (ct) {
                vault_wipe(ct, payload.len);
                free(ct);
        }
        if (payload.data)
                vault_wipe(payload.data, payload.len);   /* held every secret in the clear */
        free(payload.data);
        free(file.data);
}

/* Parse a decrypted payload buffer into items, registering each. */
static void manager_deserialize_payload(Manager *mgr, const uint8_t *payload, size_t plen) {
        Rd p = { payload, plen, 0 };
        uint32_t cn, n;

        /* collections (v2): recreate each and register its object. */
        if (rd_u32(&p, &cn) < 0)
                return;
        for (uint32_t k = 0; k < cn; k++) {
                uint8_t *cpath = NULL, *clabel = NULL;
                uint64_t created = 0, modified = 0;
                Collection *c;

                if (rd_bytes(&p, &cpath, NULL) < 0 || rd_bytes(&p, &clabel, NULL) < 0 ||
                    rd_u64(&p, &created) < 0 || rd_u64(&p, &modified) < 0) {
                        free(cpath); free(clabel);
                        return;
                }
                c = collection_new(mgr, (char *) cpath, (char *) clabel);
                free(cpath); free(clabel);
                if (!c)
                        return;
                c->created = created;
                c->modified = modified;
                (void) sd_bus_add_object_vtable(mgr->bus, &c->slot, c->path,
                                                "org.freedesktop.Secret.Collection", collection_vtable, c);
        }

        if (rd_u32(&p, &n) < 0)
                return;
        for (uint32_t k = 0; k < n; k++) {
                Item *it = calloc(1, sizeof *it);
                uint8_t *ct = NULL, *lbl = NULL, *coll = NULL, *val = NULL;
                size_t vl = 0;
                uint32_t ac = 0;
                Attr *tail = NULL;
                bool bad = false;

                if (!it)
                        return;
                if (rd_u64(&p, &it->created) < 0 || rd_u64(&p, &it->modified) < 0 ||
                    rd_bytes(&p, &ct, NULL) < 0 || rd_bytes(&p, &lbl, NULL) < 0 ||
                    rd_bytes(&p, &coll, NULL) < 0 ||
                    rd_bytes(&p, &val, &vl) < 0 || rd_u32(&p, &ac) < 0) {
                        free(ct); free(lbl); free(coll); free(val); free(it);
                        return;
                }
                it->content_type = (char *) ct;
                it->label = (char *) lbl;
                it->collection = (char *) coll;
                it->secret = val;
                it->secret_len = vl;
                for (uint32_t j = 0; j < ac && !bad; j++) {
                        uint8_t *key = NULL, *v = NULL;
                        Attr *a;
                        if (rd_bytes(&p, &key, NULL) < 0 || rd_bytes(&p, &v, NULL) < 0 ||
                            !(a = calloc(1, sizeof *a))) {
                                free(key); free(v); bad = true; break;
                        }
                        a->key = (char *) key;
                        a->val = (char *) v;
                        if (tail) tail->next = a; else it->attrs = a;
                        tail = a;
                }
                if (bad || manager_register_item(mgr, it) < 0) {
                        free_attrs(it->attrs);
                        free(it->content_type); free(it->label); free(it->secret);
                        free(it->collection); free(it->path); free(it);
                        return;
                }
        }
}

static void manager_load(Manager *mgr) {
        _cleanup_free_ char *path = NULL;
        _cleanup_free_ uint8_t *data = NULL;
        size_t len = 0;
        uint32_t version, cipher, plen;
        char magic[8];

        if (store_path(&path) < 0 || read_file(path, &data, &len) < 0)
                return;   /* no store yet — first run */

        Rd r = { data, len, 0 };
        if (rd_raw(&r, magic, 8) < 0 || memcmp(magic, "PLTFSECR", 8) != 0 ||
            rd_u32(&r, &version) < 0 || version != 2 ||
            rd_u32(&r, &cipher) < 0) {
                sd_journal_print(LOG_WARNING, "ignoring unrecognized store %s", path);
                return;
        }

        if (cipher == 0) {
                if (rd_u32(&r, &plen) < 0 || r.pos + plen > len)
                        return;
                manager_deserialize_payload(mgr, data + r.pos, plen);
        } else if (cipher == 1) {
                uint8_t nonce[VAULT_NONCE_LEN], tag[VAULT_TAG_LEN];
                _cleanup_free_ uint8_t *pt = NULL;

                if (!g_encrypting) {
                        sd_journal_print(LOG_WARNING, "store is encrypted but no vault key is loaded");
                        return;
                }
                if (rd_raw(&r, nonce, sizeof nonce) < 0 || rd_raw(&r, tag, sizeof tag) < 0 ||
                    rd_u32(&r, &plen) < 0 || r.pos + plen > len)
                        return;
                pt = malloc(plen ? plen : 1);
                if (!pt)
                        return;
                if (vault_open(g_vault_key, nonce, data + r.pos, plen, tag, pt) < 0) {
                        sd_journal_print(LOG_ERR, "cannot decrypt store (wrong key or tampered)");
                        vault_wipe(pt, plen);
                        return;
                }
                manager_deserialize_payload(mgr, pt, plen);
                vault_wipe(pt, plen);
        } else
                sd_journal_print(LOG_WARNING, "unsupported store cipher %u", cipher);
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
        sess = find_session(mgr, session);
        if (sess && sess->encrypted) {
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
                free_attrs(item->attrs); item->attrs = attrs; attrs = NULL;
                free(item->label); item->label = label; label = NULL;
                if (item->secret) vault_wipe(item->secret, item->secret_len);
                free(item->secret); item->secret = memdup(store, store_len); item->secret_len = store_len;
                free(item->content_type); item->content_type = strdup((ct && *ct) ? ct : "text/plain");
                item->modified = now_secs();
        } else {
                item = calloc(1, sizeof *item);
                if (!item) { r = -ENOMEM; goto fail; }
                item->label = label; label = NULL;
                item->attrs = attrs; attrs = NULL;
                item->secret = memdup(store, store_len); item->secret_len = store_len;
                item->content_type = strdup((ct && *ct) ? ct : "text/plain");
                item->collection = strdup(coll->path);
                item->created = item->modified = now_secs();
                if ((r = manager_register_item(mgr, item)) < 0) {
                        free_attrs(item->attrs); free(item->label); free(item->secret);
                        free(item->content_type); free(item->collection); free(item->path); free(item);
                        goto fail;
                }
                created = true;
        }

        manager_save();
        emit_item_signal(item->collection, created ? "ItemCreated" : "ItemChanged", item->path, created);
        free(dec);
        return sd_bus_reply_method_return(m, "oo", item->path, "/");

fail:
        free_attrs(attrs);
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
        int r;

        if (streq(coll->path, COLLECTION_PATH))
                return sd_bus_error_set(e, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "The default collection cannot be deleted");
        for (Item *it = mgr->items; it; it = it->next)
                if (!it->deleted && it->collection && streq(it->collection, coll->path)) {
                        it->deleted = true;
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
        manager_save();
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

static int method_session_close(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Session *sess = userdata, **pp;
        Manager *mgr = manager_instance;

        if (sess && mgr) {
                for (pp = &mgr->sessions; *pp; pp = &(*pp)->next)
                        if (*pp == sess) { *pp = sess->next; break; }
                vault_wipe(sess->aes_key, sizeof sess->aes_key);
                (void) sd_bus_slot_unref(sess->slot);   /* removes the Session object */
                free(sess->path);
                free(sess);
        }
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
        bool dh;

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
        if (dh) {
                sess->encrypted = true;
                memcpy(sess->aes_key, aes_key, VAULT_DH_KEY_LEN);
                vault_wipe(aes_key, sizeof aes_key);
        }
        r = sd_bus_add_object_vtable(mgr->bus, &sess->slot, sess->path,
                                     "org.freedesktop.Secret.Session", session_vtable, sess);
        if (r < 0) {
                vault_wipe(sess->aes_key, sizeof sess->aes_key);
                free(sess->path);
                free(sess);
                return r;
        }
        sess->next = mgr->sessions;
        mgr->sessions = sess;

        /* Output variant: (ay our_pub) for DH, (s "") for plain — plus the path. */
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
        for (Prompt **pp = &mgr->prompts; *pp; pp = &(*pp)->next)
                if (*pp == p) { *pp = p->next; break; }
        (void) sd_bus_slot_unref(p->slot);
        free(p->path);
        free(p);
}

/* Completed(dismissed, variant<ao> result) — result is the unlocked objects. */
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

/* Prompt(window-id): re-authenticate via polkit, then clear the manual lock. */
static int method_prompt_prompt(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Prompt *p = userdata;
        Manager *mgr = manager_instance;
        bool ok = polkit_check_fresh(m);
        int r;

        if (ok && mgr->manual_locked) {
                mgr->manual_locked = false;
                mgr->last_verify = now_mono();
                emit_locked_changed();
        }
        prompt_complete(mgr, p, !ok, ok ? COLLECTION_PATH : NULL);
        r = sd_bus_reply_method_return(m, NULL);
        prompt_free(mgr, p);
        return r;
}

static int method_prompt_dismiss(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Prompt *p = userdata;
        Manager *mgr = manager_instance;
        int r;

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

/* Unlock: refused while the desktop session is locked (the desktop unlock is the
 * only key). While the desktop is unlocked but an explicit Service.Lock is in
 * effect, hand back a Prompt that re-authenticates (polkit) before clearing it. */
static int method_unlock(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;

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
                r = sd_bus_add_object_vtable(mgr->bus, &p->slot, p->path,
                                             "org.freedesktop.Secret.Prompt", prompt_vtable, p);
                if (r < 0) {
                        free(p->path);
                        free(p);
                        return r;
                }
                p->next = mgr->prompts;
                mgr->prompts = p;
                return reply_lockish(m, false, p->path);   /* unlocked=[], prompt=path */
        }
        return reply_lockish(m, true, "/");   /* already unlocked */
}

static int method_get_secrets(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char **paths = NULL;
        size_t n = 0;
        const char *session;
        int r;

        if (collection_locked(mgr)) {   /* locked → release nothing */
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *empty = NULL;
                if ((r = sd_bus_message_new_method_return(m, &empty)) < 0 ||
                    (r = sd_bus_message_open_container(empty, 'a', "{o(oayays)}")) < 0 ||
                    (r = sd_bus_message_close_container(empty)) < 0)
                        return r;
                return sd_bus_send(NULL, empty, NULL);
        }

        CallerGrade grade = caller_grade(m);   /* record & report the caller */

        /* in: ao items, o session — collect the paths, then read the session. */
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
                paths[n++] = (char *) p;   /* borrowed from m, valid until m is freed */
        }
        if ((r = sd_bus_message_exit_container(m)) < 0)
                return r;
        if ((r = sd_bus_message_read(m, "o", &session)) < 0)
                return r;

        if ((r = sd_bus_message_new_method_return(m, &reply)) < 0)
                return r;
        if ((r = sd_bus_message_open_container(reply, 'a', "{o(oayays)}")) < 0)
                return r;
        for (size_t k = 0; k < n; k++) {
                Item *it = manager_find_by_path(mgr, paths[k]);
                if (!it || trust_gate(it, grade, m) != GATE_ALLOW)
                        continue;
                if ((r = sd_bus_message_open_container(reply, 'e', "o(oayays)")) < 0)
                        return r;
                if ((r = sd_bus_message_append(reply, "o", it->path)) < 0)
                        return r;
                if ((r = append_secret(reply, session, it->secret, it->secret_len, it->content_type)) < 0)
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
        int r = sd_bus_message_skip(m, "so");   /* M2: fixed default alias */
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
 * LockedHint property. Best-effort: with no graphical session the lock stays
 * manual (the Lock/Unlock methods only).
 */

static int on_session_lock(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        bool was = collection_locked(mgr);
        mgr->desktop_locked = true;
        if (!was)
                emit_locked_changed();
        return 0;
}

static int on_session_unlock(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        bool was = collection_locked(mgr);
        mgr->desktop_locked = false;
        mgr->last_verify = now_mono();           /* the screen unlock is the auth */
        if (was != collection_locked(mgr))
                emit_locked_changed();
        return 0;
}

static int on_session_props(sd_bus_message *m, void *userdata, sd_bus_error *e) {
        Manager *mgr = userdata;
        const char *iface;

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
                                        if (!locked)
                                                mgr->last_verify = now_mono();
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
        _cleanup_free_ char *session = NULL, *path = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *p;
        int r, locked = 0;

        if (sd_uid_get_display(getuid(), &session) < 0)
                return;   /* no graphical session — lock stays manual */
        if (sd_bus_open_system(&mgr->system_bus) < 0 ||
            sd_bus_attach_event(mgr->system_bus, event, SD_EVENT_PRIORITY_NORMAL) < 0)
                return;

        r = sd_bus_call_method(mgr->system_bus, "org.freedesktop.login1", "/org/freedesktop/login1",
                               "org.freedesktop.login1.Manager", "GetSession", &error, &reply, "s", session);
        if (r < 0 || sd_bus_message_read(reply, "o", &p) < 0 || !(path = strdup(p)))
                return;

        if (sd_bus_get_property_trivial(mgr->system_bus, "org.freedesktop.login1", path,
                                        "org.freedesktop.login1.Session", "LockedHint", NULL, 'b', &locked) >= 0)
                mgr->desktop_locked = locked;

        (void) sd_bus_match_signal(mgr->system_bus, NULL, "org.freedesktop.login1", path,
                                   "org.freedesktop.login1.Session", "Lock", on_session_lock, mgr);
        (void) sd_bus_match_signal(mgr->system_bus, NULL, "org.freedesktop.login1", path,
                                   "org.freedesktop.login1.Session", "Unlock", on_session_unlock, mgr);
        (void) sd_bus_match_signal(mgr->system_bus, NULL, "org.freedesktop.login1", path,
                                   "org.freedesktop.DBus.Properties", "PropertiesChanged", on_session_props, mgr);

        sd_journal_print(LOG_INFO, "tracking logind session %s (initial state: %s)",
                         session, mgr->desktop_locked ? "locked" : "unlocked");
}

/* --- Varlink: io.platformd.Secret ------------------------------------------
 *
 * A read-only admin / introspection surface over sd-varlink, the way systemd's
 * own services expose one (io.systemd.Home, io.systemd.Resolve, …). Secrets
 * never travel here — that stays on the D-Bus Secret Service. Listens on
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
                SD_JSON_BUILD_PAIR("freshWindowSec", SD_JSON_BUILD_UNSIGNED(g_fresh_window)),
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
                return 0;   /* no runtime dir → skip the admin interface */
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

/* systemd-homed storage type for this user (luks / fscrypt / directory / …), or
 * NULL when the user isn't homed-managed. Lets us cooperate with an already-
 * encrypted home instead of double-encrypting, and warn when the store would sit
 * in the clear on an unencrypted home. */
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
        manager.last_verify = now_mono();   /* the user is present at startup */
        const char *fw = getenv("SECRETD_FRESH_WINDOW_SEC");
        if (fw && *fw)
                g_fresh_window = strtoull(fw, NULL, 10);

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
                                "store kept in the clear — riding on the encrypted home (storage=%s)",
                                manager.home_storage);
                else
                        sd_journal_print(LOG_WARNING,
                                "secrets at rest are UNENCRYPTED (homed storage=%s, no vault key) — "
                                "set LoadCredentialEncrypted in the unit to protect them",
                                manager.home_storage);
        }

        if ((r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL)) < 0)
                return fail("attach bus to event loop", r);

        setup_logind_lock(&manager, event);   /* tie lock state to the desktop session */
        (void) setup_varlink(&manager, event); /* io.platformd.Secret admin interface */

        r = sd_bus_request_name(bus, SECRETS_NAME, 0);
        if (r < 0) {
                sd_journal_print(LOG_ERR, "cannot claim %s "
                                 "(another Secret Service provider already running?): %s",
                                 SECRETS_NAME, strerror(-r));
                return EXIT_FAILURE;
        }

        sd_notify(0, "READY=1\n"
                     "STATUS=Serving org.freedesktop.secrets (persistent store, plaintext)");
        sd_journal_print(LOG_INFO, "claimed %s — serving (%s store)", SECRETS_NAME,
                         g_encrypting ? "encrypted" : "plaintext");

        r = sd_event_loop(event);
        vault_wipe(g_vault_key, sizeof g_vault_key);
        if (manager.varlink)
                sd_varlink_server_unref(manager.varlink);
        free(manager.home_storage);
        if (manager.system_bus)
                sd_bus_flush_close_unref(manager.system_bus);
        if (r < 0)
                return fail("event loop", r);
        return EXIT_SUCCESS;
}
