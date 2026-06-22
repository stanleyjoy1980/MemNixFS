/* lmpfs_plugin.h — public C ABI for third-party MemNixFS plugins.
 *
 * Lets external `.dll` / `.so` modules register new VFS paths at engine
 * init time. The plugin DLL is loaded from one of:
 *
 *    $LMPFS_PLUGINS_DIR/*.dll
 *    %LOCALAPPDATA%\MemNixFS\plugins\*.dll   (Windows)
 *    ~/.local/share/memnixfs/plugins/*.so    (POSIX)
 *
 * Contract:
 *
 *   1. The plugin DLL MUST export a single C-linkage symbol:
 *
 *          int lmpfs_plugin_init(lmpfs_handle_t engine);
 *
 *      Return 0 on success, non-zero to be unloaded with a warning.
 *
 *   2. Inside `init`, the plugin calls `lmpfs_plugin_add_file()` (or
 *      `_add_dir`) one or more times to register VFS paths under
 *      `/plugins/<plugin-name>/...`. The plugin name is derived from
 *      the DLL base name (e.g. `foo.dll` → `/plugins/foo/...`).
 *
 *   3. The producer callback receives the engine handle and is
 *      expected to fill `out->data` with a malloc'd buffer of
 *      `out->length` bytes. The buffer is freed by `out->free_fn`
 *      (or `free()` if `free_fn` is NULL) after the VFS layer is
 *      done with it.
 *
 *   4. Plugins MUST NOT keep any reference to the engine handle past
 *      the lifetime of `lmpfs_plugin_init`. Each producer call is
 *      independent — the engine handle passed to the producer may
 *      differ from the one passed to init.
 *
 * Threading: producer callbacks may be invoked concurrently from
 * multiple WinFsp dispatcher threads. Plugins must serialise any
 * shared state internally.
 *
 * Example plugin (see tests/c_api/sample_plugin.cpp for the full source):
 *
 *     #include "api/lmpfs.h"
 *     #include "api/lmpfs_plugin.h"
 *
 *     static int hello_producer(lmpfs_handle_t, lmpfs_plugin_buffer_t* out) {
 *         const char msg[] = "Hello from a MemNixFS plugin!\n";
 *         out->length = sizeof(msg) - 1;
 *         out->data   = malloc(out->length);
 *         memcpy(out->data, msg, out->length);
 *         out->free_fn = NULL;     // default to free()
 *         return 0;
 *     }
 *
 *     extern "C" __declspec(dllexport)
 *     int lmpfs_plugin_init(lmpfs_handle_t eng) {
 *         return lmpfs_plugin_add_file(eng, "hello.txt", hello_producer);
 *     }
 */
#ifndef LMPFS_PLUGIN_H
#define LMPFS_PLUGIN_H

#include "api/lmpfs.h"          /* lmpfs_handle_t, LMPFS_API */

#ifdef __cplusplus
extern "C" {
#endif

/* Per-producer return buffer. */
typedef struct lmpfs_plugin_buffer {
    void*   data;
    size_t  length;
    /* Optional free function. NULL == use stdlib free(). */
    void  (*free_fn)(void* data);
} lmpfs_plugin_buffer_t;

/* Producer callback signature. Return 0 on success, non-zero on failure
 * (the engine will return an error from the read). */
typedef int (*lmpfs_plugin_file_producer)(lmpfs_handle_t          engine,
                                           lmpfs_plugin_buffer_t*  out);

/* Required entry point exported by every plugin DLL. */
typedef int (*lmpfs_plugin_init_fn)(lmpfs_handle_t engine);

/* Register a file under `/plugins/<plugin>/path`.
 *
 *   `path` is a forward-slash sub-path relative to the plugin's
 *   `/plugins/<plugin>/` root (e.g. "hello.txt", "data/blob.bin").
 *   Intermediate directories are auto-created.
 *
 * Returns 0 on success, -1 on failure (sets lmpfs_last_error).
 */
LMPFS_API int lmpfs_plugin_add_file(lmpfs_handle_t              engine,
                                     const char*                 path,
                                     lmpfs_plugin_file_producer  producer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LMPFS_PLUGIN_H */
