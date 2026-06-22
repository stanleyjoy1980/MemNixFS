#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/timeline.h"
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

ByteBuf format_crash_summary(const Engine& eng);
ByteBuf format_crash_events(const Engine& eng);
ByteBuf format_crash_call_traces(const Engine& eng);

ByteBuf format_journal_index(const Engine& eng);
ByteBuf format_journal_text_logs(const Engine& eng);
ByteBuf format_journald_entries(const Engine& eng);

std::vector<TimelineEvent> collect_crash_log_timeline_events(const Engine& eng);

} // namespace lmpfs::linux
