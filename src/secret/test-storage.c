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
        return 0;
}
