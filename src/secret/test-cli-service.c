/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#define ROOT "/org/freedesktop/secrets"
#define COLLECTION ROOT "/collection/default"
#define PROMPT ROOT "/prompt/test"

typedef struct TestService {
        const char *mode;
        bool locked;
} TestService;

static int lock_request(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        TestService *service = userdata;
        bool expected = sd_bus_message_is_method_call(message, "org.freedesktop.Secret.Service", "Lock");

        service->locked = strstr(service->mode, "wrong-state") ? !expected : expected;
        if (strncmp(service->mode, "prompt-", 7) == 0)
                return sd_bus_reply_method_return(message, "aoo", 0, PROMPT);
        if (strcmp(service->mode, "empty") == 0)
                return sd_bus_reply_method_return(message, "aoo", 0, "/");
        return sd_bus_reply_method_return(message, "aoo", 1,
                                          strcmp(service->mode, "other") == 0 ? ROOT "/collection/other" : COLLECTION,
                                          "/");
}

static int prompt_request(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        TestService *service = userdata;
        sd_bus *bus = sd_bus_message_get_bus(message);
        int r;

        if (strcmp(service->mode, "prompt-invalid") == 0)
                r = sd_bus_emit_signal(bus, PROMPT, "org.freedesktop.Secret.Prompt", "Completed",
                                       "bv", 0, "s", "invalid");
        else if (strcmp(service->mode, "prompt-empty") == 0)
                r = sd_bus_emit_signal(bus, PROMPT, "org.freedesktop.Secret.Prompt", "Completed",
                                       "bv", 0, "ao", 0);
        else
                r = sd_bus_emit_signal(bus, PROMPT, "org.freedesktop.Secret.Prompt", "Completed",
                                       "bv", strcmp(service->mode, "prompt-dismissed") == 0, "ao", 1,
                                       strcmp(service->mode, "prompt-other") == 0 ? ROOT "/collection/other" : COLLECTION);
        assert(r >= 0);
        return sd_bus_reply_method_return(message, NULL);
}

static int get_locked(sd_bus *bus, const char *path, const char *interface, const char *property,
                       sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        TestService *service = userdata;

        if (strcmp(service->mode, "state-error") == 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_FAILED, "Synthetic state failure");
        return sd_bus_message_append(reply, "b", service->locked);
}

static const sd_bus_vtable service_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Lock", "ao", "aoo", lock_request, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Unlock", "ao", "aoo", lock_request, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};
static const sd_bus_vtable collection_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Locked", "b", get_locked, 0, 0),
        SD_BUS_VTABLE_END,
};
static const sd_bus_vtable prompt_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Prompt", "s", "", prompt_request, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("Completed", "bv", 0),
        SD_BUS_VTABLE_END,
};

int main(int argc, char **argv) {
        sd_bus *bus = NULL;
        sd_event *event = NULL;
        TestService service = {};
        int r;

        assert(argc == 2);
        service.mode = argv[1];
        assert(sd_event_new(&event) >= 0);
        assert(sd_event_add_signal(event, NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, NULL, NULL) >= 0);
        assert(sd_bus_open_user(&bus) >= 0);
        assert(sd_bus_attach_event(bus, event, 0) >= 0);
        assert(sd_bus_add_object_vtable(bus, NULL, ROOT, "org.freedesktop.Secret.Service", service_vtable, &service) >= 0);
        assert(sd_bus_add_object_vtable(bus, NULL, COLLECTION, "org.freedesktop.Secret.Collection", collection_vtable, &service) >= 0);
        assert(sd_bus_add_object_vtable(bus, NULL, PROMPT, "org.freedesktop.Secret.Prompt", prompt_vtable, &service) >= 0);
        assert(sd_bus_request_name(bus, "org.freedesktop.secrets", 0) >= 0);
        puts("ready");
        fflush(stdout);
        r = sd_event_loop(event);
        sd_bus_flush_close_unref(bus);
        sd_event_unref(event);
        return r < 0 ? 1 : r;
}
