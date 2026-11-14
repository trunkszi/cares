/**
 * @file probes.hpp
 * @brief Native codegen probes for `cares::Resolver` hot paths.
 */
#pragma once

#include <cstddef>
#include <span>

extern "C" {

void cares_probe_resolver_step() noexcept;
void cares_probe_poll_flush() noexcept;
void cares_probe_timer_reconcile() noexcept;
void cares_probe_record_view(std::span<const std::byte> wire) noexcept;
}
