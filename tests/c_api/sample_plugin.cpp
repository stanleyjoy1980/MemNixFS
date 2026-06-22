/* sample_plugin.cpp — minimal MemNixFS plugin demonstrating the
 * plugin SDK. When loaded, this DLL adds two files under
 * /plugins/sample_plugin/:
 *
 *   hello.txt       a literal greeting
 *   pid_count.txt   the current process count (read via the engine API)
 *
 * Build target: a SHARED library that exports `lmpfs_plugin_init`.
 * Drop the resulting `sample_plugin.dll` into:
 *
 *   $LMPFS_PLUGINS_DIR   (any directory you control), or
 *   %LOCALAPPDATA%\MemNixFS\plugins
 *
 * Then open any dump — `/plugins/sample_plugin/` will appear in the VFS.
 */
#include "api/lmpfs.h"
#include "api/lmpfs_plugin.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

/* ---- producer callbacks ------------------------------------------------ */

static int hello_producer(lmpfs_handle_t /*eng*/, lmpfs_plugin_buffer_t* out) {
    const char msg[] = "Hello from a MemNixFS plugin!\n"
                       "Loaded from sample_plugin.dll, served at\n"
                       "/plugins/sample_plugin/hello.txt.\n";
    out->length  = sizeof(msg) - 1;
    out->data    = std::malloc(out->length);
    if (!out->data) return -1;
    std::memcpy(out->data, msg, out->length);
    out->free_fn = nullptr;       /* default to free() */
    return 0;
}

static int pid_count_producer(lmpfs_handle_t eng, lmpfs_plugin_buffer_t* out) {
    int n = lmpfs_process_count(eng);
    char buf[64];
    int  len = std::snprintf(buf, sizeof(buf), "%d processes visible\n", n);
    if (len < 0) return -1;
    out->length  = (size_t)len;
    out->data    = std::malloc(out->length);
    if (!out->data) return -1;
    std::memcpy(out->data, buf, out->length);
    out->free_fn = nullptr;
    return 0;
}

/* ---- required init export ---------------------------------------------- */

#ifdef _WIN32
extern "C" __declspec(dllexport)
#else
extern "C"
#endif
int lmpfs_plugin_init(lmpfs_handle_t eng) {
    int r1 = lmpfs_plugin_add_file(eng, "hello.txt",      hello_producer);
    int r2 = lmpfs_plugin_add_file(eng, "pid_count.txt",  pid_count_producer);
    return (r1 == 0 && r2 == 0) ? 0 : -1;
}
