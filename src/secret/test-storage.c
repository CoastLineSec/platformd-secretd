/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define main secretd_main
#include "secretd.c"
#undef main

static unsigned fault;

ssize_t __real_read(int fd, void *data, size_t size);
ssize_t __real_write(int fd, const void *data, size_t size);
int __real_fsync(int fd);
int __real_rename(const char *from, const char *to);

ssize_t __wrap_read(int fd, void *data, size_t size) {
        if (fault == 5) {
                errno = EIO;
                return -1;
        }
        return __real_read(fd, data, size);
}

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

static void test_duplicate_attributes(void) {
        Manager manager = {};
        Buf payload = {};

        assert(collection_new(&manager, COLLECTION_PATH, "test"));
        assert(buf_u32(&payload, 0) >= 0);
        assert(buf_u32(&payload, 1) >= 0);
        assert(buf_u64(&payload, 0) >= 0);
        assert(buf_u64(&payload, 0) >= 0);
        assert(buf_str(&payload, "text/plain") >= 0);
        assert(buf_str(&payload, "test") >= 0);
        assert(buf_str(&payload, COLLECTION_PATH) >= 0);
        assert(buf_str(&payload, "synthetic") >= 0);
        assert(buf_u32(&payload, 2) >= 0);
        assert(buf_str(&payload, "platformd.policy") >= 0);
        assert(buf_str(&payload, "fresh-verification") >= 0);
        assert(buf_str(&payload, "platformd.policy") >= 0);
        assert(buf_str(&payload, "trusted-platform") >= 0);
        assert(manager_deserialize_payload(&manager, payload.data, payload.len, 2) == -EBADMSG);
        assert(!manager.items);
        collection_destroy(&manager, manager.collections);
        vault_wipe(payload.data, payload.len);
        free(payload.data);
}

static void test_persistence_status(void) {
        char directory[] = "/tmp/platformd-storage-status.XXXXXX";
        _cleanup_free_ char *path = NULL;
        Manager manager = {};

        assert(mkdtemp(directory));
        assert(setenv("XDG_DATA_HOME", directory, 1) == 0);
        assert(collection_new(&manager, COLLECTION_PATH, "test"));
        manager_instance = &manager;
        assert(store_path(&path) == 0);

        for (unsigned phase = 1; phase <= 4; phase++) {
                g_store_loaded = true;
                g_store_readonly = false;
                g_store_uncertain = false;
                g_store_error = 0;
                fault = phase;
                assert(manager_save() == (phase == 4 ? -EUCLEAN : -EIO));
                assert(g_store_loaded);
                assert(g_store_error == (phase == 4 ? EUCLEAN : EIO));
                assert(g_store_readonly == (phase == 4));
                assert(g_store_uncertain == (phase == 4));
                fault = 0;
                if (phase == 4) {
                        assert(manager_save() == -EROFS);
                        assert(g_store_error == EUCLEAN);
                } else {
                        assert(manager_save() == 0);
                        assert(g_store_error == 0);
                }
        }

        manager_instance = NULL;
        collection_destroy(&manager, manager.collections);
        assert(unlink(path) == 0);
        *strrchr(path, '/') = 0;
        assert(rmdir(path) == 0);
        assert(rmdir(directory) == 0);
}

static void test_load_status(void) {
        char directory[] = "/tmp/platformd-storage-load.XXXXXX";
        _cleanup_free_ char *path = NULL;
        _cleanup_(sensitive_buffer_clear) SensitiveBuffer before = {}, after = {};
        Manager manager = {};

        assert(mkdtemp(directory));
        assert(setenv("XDG_DATA_HOME", directory, 1) == 0);
        assert(collection_new(&manager, COLLECTION_PATH, "persisted"));
        manager_instance = &manager;
        fault = 0;
        g_store_readonly = g_store_uncertain = false;
        assert(manager_save() == 0);
        assert(store_path(&path) == 0);
        assert(read_file(path, &before.data, &before.size) == 0);
        collection_destroy(&manager, manager.collections);
        assert(collection_new(&manager, COLLECTION_PATH, "initial"));

        g_store_loaded = false;
        fault = 5;
        manager_load(&manager);
        assert(!g_store_loaded);
        assert(g_store_readonly);
        assert(g_store_error == EIO);
        assert(streq(manager.collections->label, "initial"));
        assert(manager_save() == -EROFS);
        assert(g_store_error == EIO);

        g_store_readonly = false;
        g_store_error = 0;
        g_encrypting = true;
        fault = 1;
        manager_load(&manager);
        assert(g_store_loaded);
        assert(g_store_readonly);
        assert(!g_store_encrypted);
        assert(g_store_error == EIO);
        assert(streq(manager.collections->label, "persisted"));
        assert(manager_save() == -EROFS);
        assert(g_store_error == EIO);
        fault = 0;
        assert(read_file(path, &after.data, &after.size) == 0);
        assert(before.size == after.size && memcmp(before.data, after.data, before.size) == 0);

        manager_instance = NULL;
        collection_destroy(&manager, manager.collections);
        assert(unlink(path) == 0);
        *strrchr(path, '/') = 0;
        assert(rmdir(path) == 0);
        assert(rmdir(directory) == 0);
}

int main(void) {
        char directory[] = "/tmp/platformd-storage.XXXXXX", path[sizeof directory + 16];

        assert(mkdtemp(directory));
        assert(snprintf(path, sizeof path, "%s/store", directory) > 0);
        for (unsigned phase = 1; phase <= 4; phase++) {
                uint8_t *data = NULL;
                size_t size = 0;

                fault = 0;
                g_store_readonly = false;
                assert(write_atomic(path, (const uint8_t *) "old", 3, 0600) == 0);
                fault = phase;
                assert(write_atomic(path, (const uint8_t *) "new", 3, 0600) ==
                       (phase == 4 ? -EUCLEAN : -EIO));
                assert(g_store_readonly == (phase == 4));
                assert(read_file(path, &data, &size) == 0);
                assert(size == 3 && memcmp(data, phase == 4 ? "new" : "old", size) == 0);
                free(data);
        }
        assert(unlink(path) == 0);
        assert(rmdir(directory) == 0);
        test_duplicate_attributes();
        test_persistence_status();
        test_load_status();
        return 0;
}
