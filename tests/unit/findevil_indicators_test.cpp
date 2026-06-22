#include "os/linux/findevil.h"
#include <cassert>

using namespace lmpfs::linux;

int main() {
    assert(severity_rank("HIGH") < severity_rank("MEDIUM"));
    assert(severity_rank("MEDIUM") < severity_rank("REVIEW"));
    assert(severity_rank("REVIEW") < severity_rank("INFO"));
    assert(severity_rank("UNKNOWN") == severity_rank("INFO"));
    return 0;
}
