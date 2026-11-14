#include <ares.h>
#include <netdb.h>
#include <netinet/in.h>

#include <array>
#include <bit>
#include <cares/channel/callback_table.hpp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

namespace {

int g_failed = 0;
std::size_t g_frees = 0;

void Check(bool ok, const char* name) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", name);
    ++g_failed;
  }
}

void* HookMalloc(std::size_t bytes) { return std::malloc(bytes); }
void HookFree(void* ptr) {
  if (ptr != nullptr) ++g_frees;
  std::free(ptr);
}
void* HookRealloc(void* ptr, std::size_t bytes) { return std::realloc(ptr, bytes); }

cares::Error SlabFull() { return cares::Error::CapacityExhausted(); }

struct HostProbe {
  cares::CallbackTable<4>* table{nullptr};
  cares::QueryHandle handle{};
  int calls{0};
  bool ok{false};
  cares::Error error{};
  cares::HostResult host{};
  bool valid_during{false};
  std::size_t active_during{0};

  void OnHost(cares::Result<cares::HostResult> result) noexcept {
    ++calls;
    valid_during = table->IsValid(handle);
    active_during = table->ActiveCount();
    if (result) {
      ok = true;
      host = *result;
    } else {
      error = result.error();
    }
  }
};

struct DnsProbe {
  int calls{0};
  const ares_dns_record_t* raw{nullptr};
  cares::Error error{};
  void OnDns(cares::Result<cares::DnsRecordRef> result) noexcept {
    ++calls;
    if (result)
      raw = result->Raw();
    else
      error = result.error();
  }
};

struct AddrProbe {
  int calls{0};
  bool ok{false};
  cares::Error error{};
  cares::AddressInfoResult info{};
  void OnAddr(cares::Result<cares::AddressInfoResult> result) noexcept {
    ++calls;
    if (result) {
      ok = true;
      info = *result;
    } else {
      error = result.error();
    }
  }
};

struct NameProbe {
  int calls{0};
  bool ok{false};
  cares::Error error{};
  cares::NameInfoResult info{};
  void OnName(cares::Result<cares::NameInfoResult> result) noexcept {
    ++calls;
    if (result) {
      ok = true;
      info = *result;
    } else {
      error = result.error();
    }
  }
};

struct NopHost {
  void OnHost(cares::Result<cares::HostResult>) noexcept {}
};

hostent MakeV4(char* name, char** addrs) {
  hostent host{};
  host.h_name = name;
  host.h_addrtype = AF_INET;
  host.h_length = 4;
  host.h_addr_list = addrs;
  return host;
}

using AddrFn = void (*)(void*, int, int, struct ares_addrinfo*) noexcept;
using NameFn = void (*)(void*, int, int, char*, char*) noexcept;

void ArmThenDeliver() {
  cares::CallbackTable<4> table;
  ares_host_callback host_cb = &cares::CallbackTable<4>::AresHostCallback;
  ares_callback_dnsrec dns_cb = &cares::CallbackTable<4>::AresDnsRecCallback;
  ares_addrinfo_callback addr_cb = &cares::CallbackTable<4>::AresAddrInfoCallback;
  ares_nameinfo_callback name_cb = &cares::CallbackTable<4>::AresNameInfoCallback;
  Check(host_cb != nullptr && dns_cb != nullptr && addr_cb != nullptr && name_cb != nullptr, "fns");
  static_cast<void>(addr_cb);
  static_cast<void>(name_cb);

  HostProbe probe;
  probe.table = &table;
  auto handle = table.AllocateHost(uarch::bind<&HostProbe::OnHost>(probe));
  Check(handle.has_value(), "arm");
  if (!handle) return;
  probe.handle = *handle;
  Check(table.ActiveCount() == 1, "active");
  Check(table.IsValid(*handle), "valid");
  table.BindQid(*handle, 42);

  auto name = std::to_array("host.example");
  std::array<unsigned char, 4> addr{{1, 2, 3, 4}};
  std::array<char*, 2> addrs{{reinterpret_cast<char*>(addr.data()), nullptr}};
  hostent host = MakeV4(name.data(), addrs.data());
  host_cb(table.SlotContextPtr(*handle), ARES_SUCCESS, 0, &host);
  Check(probe.calls == 1 && probe.ok, "delivered");
  Check(probe.valid_during && probe.active_during == 1, "during");
  Check(probe.host.CanonicalName() == "host.example", "name");
  Check(probe.host.address_count == 1, "count");
  Check(probe.host.addresses[0].v4[0] == 1 && probe.host.addresses[0].v4[3] == 4, "bytes");
  Check(table.ActiveCount() == 0, "released");
  Check(!table.IsValid(*handle), "stale_after");

  DnsProbe dns;
  auto dns_handle = table.AllocateDnsRec(uarch::bind<&DnsProbe::OnDns>(dns));
  Check(dns_handle.has_value(), "dns_arm");
  if (!dns_handle) return;
  int token = 0;
  const auto* rec = reinterpret_cast<const ares_dns_record_t*>(&token);
  dns_cb(table.SlotContextPtr(*dns_handle), ARES_SUCCESS, 0, rec);
  Check(dns.calls == 1 && dns.raw == rec, "dns_ptr");
}

void cancel_drops_callback() {
  cares::CallbackTable<4> table;
  HostProbe probe;
  probe.table = &table;
  auto handle = table.AllocateHost(uarch::bind<&HostProbe::OnHost>(probe));
  Check(handle.has_value(), "arm");
  if (!handle) return;
  probe.handle = *handle;
  Check(table.CancelSlot(*handle), "cancel");
  Check(table.ActiveCount() == 1, "still_active");
  Check(table.IsValid(*handle), "still_valid");
  Check(!table.CancelSlot(*handle), "second");
  auto name = std::to_array("gone.example");
  std::array<unsigned char, 4> addr{{9, 9, 9, 9}};
  std::array<char*, 2> addrs{{reinterpret_cast<char*>(addr.data()), nullptr}};
  hostent host = MakeV4(name.data(), addrs.data());
  cares::CallbackTable<4>::AresHostCallback(table.SlotContextPtr(*handle), ARES_SUCCESS, 0, &host);
  Check(probe.calls == 0, "not_called");
  Check(table.ActiveCount() == 0, "freed");
}

void stale_generation_rejected() {
  cares::CallbackTable<4> table;
  HostProbe probe;
  probe.table = &table;
  auto handle = table.AllocateHost(uarch::bind<&HostProbe::OnHost>(probe));
  Check(handle.has_value(), "arm");
  if (!handle) return;
  probe.handle = *handle;
  cares::CallbackTable<4>::AresHostCallback(table.SlotContextPtr(*handle), ARES_ENOTFOUND, 0, nullptr);
  Check(probe.calls == 1 && !probe.ok, "error_delivered");
  Check(probe.error == cares::Error::FromAres(ARES_ENOTFOUND), "status");
  Check(!table.CancelSlot(*handle), "stale_cancel");
  Check(table.SlotContextPtr(*handle) == nullptr, "stale_arg");
  table.BindQid(*handle, 1);
  Check(!table.IsValid(*handle), "stale_qid");
}

void CapacityExhausted() {
  cares::CallbackTable<1> table;
  NopHost first;
  NopHost second;
  auto ok = table.AllocateHost(uarch::bind<&NopHost::OnHost>(first));
  auto full = table.AllocateHost(uarch::bind<&NopHost::OnHost>(second));
  Check(ok.has_value(), "first");
  Check(!full && full.error() == SlabFull(), "second");
  Check(table.ActiveCount() == 1, "one");
  cares::HostCallback empty;
  auto invalid = table.AllocateHost(empty);
  Check(!invalid && invalid.error() == cares::Error::InvalidArgument(), "empty_cb");
}

void ReclaimAbortsQuiet() {
  cares::CallbackTable<4> table;
  HostProbe probe;
  probe.table = &table;
  auto handle = table.AllocateHost(uarch::bind<&HostProbe::OnHost>(probe));
  Check(handle.has_value(), "arm");
  if (!handle) return;
  probe.handle = *handle;
  void* arg = table.SlotContextPtr(*handle);
  table.ReclaimAllAborted();
  Check(table.ActiveCount() == 1, "waiting");
  Check(table.IsValid(*handle), "still_held");
  cares::CallbackTable<4>::AresHostCallback(arg, ARES_SUCCESS, 0, nullptr);
  Check(probe.calls == 0, "quiet");
  Check(table.ActiveCount() == 0, "freed");
}

void generation_wraps_slot() {
  cares::CallbackTable<1> table;
  NopHost probe;
  bool failed = false;
  for (int i = 0; i < 70000; ++i) {
    auto handle = table.AllocateHost(uarch::bind<&NopHost::OnHost>(probe));
    if (!handle || !handle->IsValid() || handle->Generation() == 0) {
      failed = true;
      break;
    }
    cares::CallbackTable<1>::AresHostCallback(table.SlotContextPtr(*handle), ARES_ENOTFOUND, 0, nullptr);
  }
  Check(!failed, "cycles");
  Check(table.ActiveCount() == 0, "idle");
  auto again = table.AllocateHost(uarch::bind<&NopHost::OnHost>(probe));
  Check(again.has_value() && again->IsValid(), "reuse");
}

void HostentStackDecoded() {
  cares::CallbackTable<4> table;
  HostProbe probe;
  probe.table = &table;
  auto handle = table.AllocateHost(uarch::bind<&HostProbe::OnHost>(probe));
  Check(handle.has_value(), "arm");
  if (!handle) return;
  probe.handle = *handle;
  std::array<char, 258> name{{}};
  for (std::size_t i = 0; i < 257; ++i) name[i] = 'n';
  name[257] = '\0';
  std::array<unsigned char, 4> addr{{1, 1, 1, 1}};
  std::array<char*, 2> addrs{{reinterpret_cast<char*>(addr.data()), nullptr}};
  hostent host = MakeV4(name.data(), addrs.data());
  cares::CallbackTable<4>::AresHostCallback(table.SlotContextPtr(*handle), ARES_SUCCESS, 0, &host);
  Check(probe.calls == 1 && !probe.ok, "long_name");
  Check(probe.error == cares::Error::CapacityExhausted(), "cap");

  HostProbe v6probe;
  v6probe.table = &table;
  auto v6handle = table.AllocateHost(uarch::bind<&HostProbe::OnHost>(v6probe));
  Check(v6handle.has_value(), "v6arm");
  if (!v6handle) return;
  v6probe.handle = *v6handle;
  auto v6name = std::to_array("v6.example");
  std::array<unsigned char, 16> raw{{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
  std::array<char*, 2> v6addrs{{reinterpret_cast<char*>(raw.data()), nullptr}};
  hostent v6{};
  v6.h_name = v6name.data();
  v6.h_addrtype = AF_INET6;
  v6.h_length = 16;
  v6.h_addr_list = v6addrs.data();
  cares::CallbackTable<4>::AresHostCallback(table.SlotContextPtr(*v6handle), ARES_SUCCESS, 0, &v6);
  Check(v6probe.ok && v6probe.host.addresses[0].IsV6(), "v6");
  Check(v6probe.host.addresses[0].v6[0] == 0x20 && v6probe.host.addresses[0].v6[15] == 1, "v6bytes");

  HostProbe bad;
  bad.table = &table;
  auto bad_handle = table.AllocateHost(uarch::bind<&HostProbe::OnHost>(bad));
  if (!bad_handle) return;
  bad.handle = *bad_handle;
  cares::CallbackTable<4>::AresHostCallback(table.SlotContextPtr(*bad_handle), ARES_SUCCESS, 0, nullptr);
  Check(bad.calls == 1 && bad.error == cares::Error::BadResponse(), "null_host");
}

ares_addrinfo* MakeAddrInfo() {
  auto* info = static_cast<ares_addrinfo*>(HookMalloc(sizeof(ares_addrinfo)));
  auto* node = static_cast<ares_addrinfo_node*>(HookMalloc(sizeof(ares_addrinfo_node)));
  auto* sa = static_cast<sockaddr_in*>(HookMalloc(sizeof(sockaddr_in)));
  auto* cname = static_cast<ares_addrinfo_cname*>(HookMalloc(sizeof(ares_addrinfo_cname)));
  char* name = static_cast<char*>(HookMalloc(5));
  char* alias = static_cast<char*>(HookMalloc(6));
  char* cname_name = static_cast<char*>(HookMalloc(12));
  if (info == nullptr || node == nullptr || sa == nullptr || cname == nullptr || name == nullptr || alias == nullptr ||
      cname_name == nullptr) {
    return nullptr;
  }
  std::memset(info, 0, sizeof(*info));
  std::memset(node, 0, sizeof(*node));
  std::memset(sa, 0, sizeof(*sa));
  std::memset(cname, 0, sizeof(*cname));
  std::memcpy(name, "dns.", 5);
  std::memcpy(alias, "alias", 6);
  std::memcpy(cname_name, "cname.local", 12);
  sa->sin_family = AF_INET;
  sa->sin_port = (std::endian::native == std::endian::little ? std::byteswap(std::uint16_t{53}) : std::uint16_t{53});
  sa->sin_addr = std::bit_cast<in_addr>(cares::Ipv4Bytes{8, 8, 4, 4});
  node->ai_ttl = 30;
  node->ai_socktype = SOCK_STREAM;
  node->ai_protocol = IPPROTO_TCP;
  node->ai_addr = reinterpret_cast<sockaddr*>(sa);
  node->ai_addrlen = sizeof(*sa);
  cname->ttl = 15;
  cname->alias = alias;
  cname->name = cname_name;
  info->name = name;
  info->nodes = node;
  info->cnames = cname;
  return info;
}

void AddrinfoFreeHook() {
  const int init = ares_library_init_mem(ARES_LIB_INIT_ALL, HookMalloc, HookFree, HookRealloc);
  Check(init == ARES_SUCCESS, "init_mem");
  if (init != ARES_SUCCESS) return;
  cares::CallbackTable<4> table;
  AddrProbe probe;
  auto handle = table.AllocateAddrInfo(uarch::bind<&AddrProbe::OnAddr>(probe));
  Check(handle.has_value(), "arm");
  if (!handle) return;
  ares_addrinfo* info = MakeAddrInfo();
  Check(info != nullptr, "built");
  if (info == nullptr) return;
  const std::size_t before = g_frees;
  AddrFn addr_cb = &cares::CallbackTable<4>::AresAddrInfoCallback;
  addr_cb(table.SlotContextPtr(*handle), ARES_SUCCESS, 0, info);
  Check(probe.calls == 1 && probe.ok, "decoded");
  Check(probe.info.name_len == 4, "name_len");
  Check(std::string_view(probe.info.name.data(), probe.info.name_len) == "dns.", "name");
  Check(probe.info.node_count == 1 && probe.info.nodes[0].port == 53, "port");
  Check(probe.info.nodes[0].ttl == 30, "ttl");
  Check(probe.info.nodes[0].ip.v4[0] == 8 && probe.info.nodes[0].ip.v4[3] == 4, "ip");
  Check(probe.info.cname_count == 1, "cname");
  Check(g_frees == before + 7, "freed_seven");
  Check(table.ActiveCount() == 0, "released");

  HostProbe host_probe;
  host_probe.table = &table;
  auto host_handle = table.AllocateHost(uarch::bind<&HostProbe::OnHost>(host_probe));
  Check(host_handle.has_value(), "host_arm");
  if (!host_handle) return;
  host_probe.handle = *host_handle;
  auto other = table.AllocateAddrInfo(uarch::bind<&AddrProbe::OnAddr>(probe));
  Check(other.has_value(), "other");
  if (!other) return;
  const std::size_t mid = g_frees;
  auto* stray = static_cast<ares_addrinfo*>(HookMalloc(sizeof(ares_addrinfo)));
  Check(stray != nullptr, "stray");
  if (stray == nullptr) return;
  std::memset(stray, 0, sizeof(*stray));
  cares::CallbackTable<4>::AresAddrInfoCallback(table.SlotContextPtr(*host_handle), ARES_SUCCESS, 0, stray);
  Check(host_probe.calls == 0, "mismatch_quiet");
  Check(g_frees == mid + 1, "mismatch_freed");
  Check(table.ActiveCount() == 1, "addr_kept");
  Check(table.IsValid(*other) && !table.IsValid(*host_handle), "host_released");
  cares::CallbackTable<4>::AresAddrInfoCallback(table.SlotContextPtr(*other), ARES_ENODATA, 0, nullptr);
  Check(probe.calls == 2 && probe.error == cares::Error::FromAres(ARES_ENODATA), "other_error");
  Check(table.ActiveCount() == 0, "both_done");
  ares_library_cleanup();
}

void NameinfoStackStrings() {
  cares::CallbackTable<4> table;
  NameProbe probe;
  auto handle = table.AllocateNameInfo(uarch::bind<&NameProbe::OnName>(probe));
  Check(handle.has_value(), "arm");
  if (!handle) return;
  auto node = std::to_array("node.example");
  auto service = std::to_array("https");
  NameFn name_cb = &cares::CallbackTable<4>::AresNameInfoCallback;
  name_cb(table.SlotContextPtr(*handle), ARES_SUCCESS, 0, node.data(), service.data());
  Check(probe.ok, "ok");
  Check(probe.info.Node() == "node.example", "node");
  Check(probe.info.Service() == "https", "service");
  Check(node[0] == 'n' && service[0] == 'h', "not_freed");

  NameProbe empty;
  auto empty_handle = table.AllocateNameInfo(uarch::bind<&NameProbe::OnName>(empty));
  if (!empty_handle) return;
  cares::CallbackTable<4>::AresNameInfoCallback(table.SlotContextPtr(*empty_handle), ARES_SUCCESS, 0, nullptr, nullptr);
  Check(empty.ok && empty.info.node_len == 0 && empty.info.service_len == 0, "empty");

  NameProbe long_name;
  auto long_handle = table.AllocateNameInfo(uarch::bind<&NameProbe::OnName>(long_name));
  if (!long_handle) return;
  std::array<char, 258> big{{}};
  for (std::size_t i = 0; i < 257; ++i) big[i] = 'z';
  big[257] = '\0';
  cares::CallbackTable<4>::AresNameInfoCallback(table.SlotContextPtr(*long_handle), ARES_SUCCESS, 0, big.data(),
                                                service.data());
  Check(long_name.calls == 1 && long_name.error == cares::Error::CapacityExhausted(), "long_node");
}

}  // namespace

int main() {
  ArmThenDeliver();
  cancel_drops_callback();
  stale_generation_rejected();
  CapacityExhausted();
  ReclaimAbortsQuiet();
  generation_wraps_slot();
  HostentStackDecoded();
  AddrinfoFreeHook();
  NameinfoStackStrings();
  if (g_failed != 0) {
    std::fprintf(stderr, "callback_table_test failed %d\n", g_failed);
    return 1;
  }
  std::fprintf(stdout, "ok callback_table_test\n");
  return 0;
}
