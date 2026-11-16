/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <systemd/sd-id128.h>

typedef struct TestHome {
        sd_event *event;
        sd_event_source *timer;
        sd_bus_message *request;
        const char *mode;
} TestHome;

static int reply_storage(sd_event_source *source, uint64_t usec, void *userdata) {
        TestHome *home = userdata;
        sd_id128_t machine;
        char id[SD_ID128_STRING_MAX], *json = NULL;
        int r;

        assert(sd_id128_get_machine(&machine) >= 0);
        assert(asprintf(&json, "{\"binding\":{\"%s\":{\"storage\":\"luks\"}}}",
                        sd_id128_to_string(machine, id)) >= 0);
        r = sd_bus_reply_method_return(home->request, "sbo", json, 0, "/");
        free(json);
        assert(r >= 0);
        assert(sd_bus_flush(sd_bus_message_get_bus(home->request)) >= 0);
        home->request = sd_bus_message_unref(home->request);
        home->timer = sd_event_source_unref(home->timer);
        puts("replied");
        fflush(stdout);
        return 0;
}

static int get_record(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        TestHome *home = userdata;

        assert(!home->request);
        if (sd_bus_message_is_method_call(message, "org.freedesktop.home1.Manager", "GetUserRecordByUID")) {
                uint32_t uid;

                assert(sd_bus_message_read(message, "u", &uid) > 0);
                assert(uid == getuid());
        }
        puts("received");
        fflush(stdout);
        if (strcmp(home->mode, "malformed") == 0)
                return sd_bus_reply_method_return(message, "sbo", "{", 0, "/");
        if (strcmp(home->mode, "disconnect") == 0) {
                assert(sd_event_exit(home->event, 0) >= 0);
                return 1;
        }
        home->request = sd_bus_message_ref(message);
        if (strcmp(home->mode, "hold") == 0)
                return 1;
        if (strcmp(home->mode, "delayed") == 0) {
                assert(sd_event_add_time_relative(home->event, &home->timer, CLOCK_MONOTONIC,
                                                  3U * 1000000U, 0, reply_storage, home) >= 0);
                return 1;
        }
        assert(strcmp(home->mode, "valid") == 0);
        assert(reply_storage(NULL, 0, home) >= 0);
        return 1;
}

static const sd_bus_vtable home_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("GetUserRecordByName", "s", "sbo", get_record, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUserRecordByUID", "u", "sbo", get_record, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

int main(int argc, char **argv) {
        sd_bus *bus = NULL;
        TestHome home = {};
        int r;

        assert(argc == 2);
        home.mode = argv[1];
        assert(sd_event_new(&home.event) >= 0);
        assert(sd_event_add_signal(home.event, NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, NULL, NULL) >= 0);
        assert(sd_bus_open_user(&bus) >= 0);
        assert(sd_bus_attach_event(bus, home.event, 0) >= 0);
        assert(sd_bus_add_object_vtable(bus, NULL, "/org/freedesktop/home1",
                                       "org.freedesktop.home1.Manager", home_vtable, &home) >= 0);
        assert(sd_bus_request_name(bus, "org.freedesktop.home1", 0) >= 0);
        puts("ready");
        fflush(stdout);
        r = sd_event_loop(home.event);
        sd_bus_message_unref(home.request);
        sd_event_source_unref(home.timer);
        sd_bus_flush_close_unref(bus);
        sd_event_unref(home.event);
        return r < 0 ? EXIT_FAILURE : r;
}
