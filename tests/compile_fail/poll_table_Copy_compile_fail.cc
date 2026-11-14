// expected-error: PollTable slots are not copyable
#include <cares/resolver/poll_table.hpp>

void CopyPollTable(cares::PollTable<4>& table) {
  cares::PollTable<4> copied = table;
  static_cast<void>(copied);
}

int main() { return 0; }
