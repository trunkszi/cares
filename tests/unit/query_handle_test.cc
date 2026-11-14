#include <cares/types/query_handle.hpp>
int main() {
  volatile std::uint16_t slot = 65535;
  volatile std::uint16_t generation = 65535;
  volatile std::uint32_t qid = 0xffffffffU;
  const auto handle = cares::QueryHandle::Pack(slot, generation, qid);
  if (handle.raw != 0xffffffffffffffffULL) return 1;
  if (handle.Slot() != 65535 || handle.Generation() != 65535 || handle.Qid() != 0xffffffffU) return 2;
  if (cares::QueryHandle{}.IsValid()) return 3;
  if (cares::QueryHandle::Pack(7, 3) == cares::QueryHandle::Pack(7, 4)) return 4;
  return 0;
}
