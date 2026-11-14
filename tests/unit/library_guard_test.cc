#include <cares/channel/library_guard.hpp>
#include <cstdio>
#include <utility>

namespace {

int g_failed = 0;

void Check(bool ok, const char* name) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", name);
    ++g_failed;
  }
}

void AcquirePairsCleanup() {
  const auto before = cares::LibraryGuard::Holders();
  {
    cares::LibraryGuard idle;
    Check(!idle.IsActive(), "default_inactive");
    Check(cares::LibraryGuard::Holders() == before, "default_holders");
    auto guard = cares::LibraryGuard::Acquire();
    Check(guard.has_value(), "acquire");
    if (!guard) return;
    Check(guard->IsActive(), "active");
    Check(guard->Owns(), "owns");
    Check(cares::LibraryGuard::Holders() == before + 1, "holders_up");
  }
  Check(cares::LibraryGuard::Holders() == before, "holders_down");
}

void SecondGuardKeepsInit() {
  const auto before = cares::LibraryGuard::Holders();
  auto first = cares::LibraryGuard::Acquire();
  auto second = cares::LibraryGuard::Acquire();
  Check(first.has_value() && second.has_value(), "both");
  Check(cares::LibraryGuard::Holders() == before + 2, "two_holders");
  second = cares::LibraryGuard{};
  Check(cares::LibraryGuard::Holders() == before + 1, "one_left");
  Check(first->IsActive(), "first_still_owns");
  first = cares::LibraryGuard{};
  Check(cares::LibraryGuard::Holders() == before, "both_released");
}

void MoveTransfersOwnership() {
  const auto before = cares::LibraryGuard::Holders();
  auto source = cares::LibraryGuard::Acquire();
  Check(source.has_value(), "acquire");
  if (!source) return;
  cares::LibraryGuard moved = std::move(*source);
  Check(!source->IsActive(), "source_cleared");
  Check(moved.IsActive(), "dest_owns");
  Check(cares::LibraryGuard::Holders() == before + 1, "one_init");
  auto extra = cares::LibraryGuard::Acquire();
  Check(extra.has_value(), "extra");
  if (!extra) return;
  moved = std::move(*extra);
  Check(!extra->IsActive(), "extra_cleared");
  Check(moved.IsActive(), "assign_owns");
  Check(cares::LibraryGuard::Holders() == before + 1, "assign_released_previous");
}

void ThreadingDisabledOk() {
  auto result = cares::LibraryGuard::EnsureThreadingDisabled();
  Check(result.has_value(), "threads_off");
  if (!result) Check(false, "threads_error");
}

}  // namespace

int main() {
  AcquirePairsCleanup();
  SecondGuardKeepsInit();
  MoveTransfersOwnership();
  ThreadingDisabledOk();
  if (g_failed != 0) {
    std::fprintf(stderr, "library_guard_test failed %d\n", g_failed);
    return 1;
  }
  std::fprintf(stdout, "ok library_guard_test\n");
  return 0;
}
