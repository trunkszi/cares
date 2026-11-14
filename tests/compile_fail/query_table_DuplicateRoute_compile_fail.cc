// expected-error: duplicate query route
#include <cares/query_table/query_table.hpp>

struct[[= cares::notes::QueryRoute("Example.COM.", cares::DnsType::A)]] LeftRoute {};
struct[[= cares::notes::QueryRoute("example.com", cares::DnsType::A)]] RightRoute {};

using DuplicateTable = cares::QueryTable<LeftRoute, RightRoute>;

int main() {
  DuplicateTable table;
  return table.kRouteCount == 2 ? 0 : 1;
}
