/**
 * @file cares.hpp
 * @brief Umbrella header for the `cares` Proactor DNS framework.
 */
#pragma once

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#include <cares/channel/callback_table.hpp>
#include <cares/channel/channel_core.hpp>
#include <cares/channel/completion_words.hpp>
#include <cares/channel/library_guard.hpp>
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
#include <cares/channel/options.hpp>
#include <cares/channel/socket_bridge.hpp>
#include <cares/channel/timer_state.hpp>
#include <cares/error/ares_error.hpp>
#include <cares/query_table/query_table.hpp>
#include <cares/record/dns_record.hpp>
#include <cares/record/record_extract.hpp>
#include <cares/record/record_rr.hpp>
#include <cares/resolver/dns_cache.hpp>
#include <cares/resolver/poll_table.hpp>
#include <cares/resolver/resolver.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/endpoint.hpp>
#include <cares/types/host_types.hpp>
#include <cares/types/query_handle.hpp>
