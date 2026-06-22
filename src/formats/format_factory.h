#pragma once
#include "formats/physical_layer.h"
#include <memory>

namespace lmpfs {

// Sniffs the file, picks Raw / LiME / AVML, returns the right PhysicalLayer.
std::unique_ptr<PhysicalLayer> open_physical_layer(std::unique_ptr<MemorySource> src);

// Format-specific factories (also used by tests).
std::unique_ptr<PhysicalLayer> open_raw_physical  (std::unique_ptr<MemorySource> src);
std::unique_ptr<PhysicalLayer> open_lime_physical (std::unique_ptr<MemorySource> src);
std::unique_ptr<PhysicalLayer> open_avml_physical (std::unique_ptr<MemorySource> src);
std::unique_ptr<PhysicalLayer> open_kdump_physical(std::unique_ptr<MemorySource> src);

} // namespace lmpfs
