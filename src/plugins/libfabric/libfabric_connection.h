/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 Amazon.com, Inc. and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef NIXL_SRC_PLUGINS_LIBFABRIC_LIBFABRIC_CONNECTION_H
#define NIXL_SRC_PLUGINS_LIBFABRIC_LIBFABRIC_CONNECTION_H

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "libfabric/libfabric_rail.h"

#include <memory>

class nixlLibfabricRailManager;

/** Multi-rail connection metadata for remote agents */
struct nixlLibfabricConnection : public nixlBackendConnMD {
    nixlLibfabricConnection(const std::string &remote_agent, size_t agent_index);

    /** Removes the peer's addresses from every local rail's AV (see releaseAddresses()). */
    ~nixlLibfabricConnection();

    nixlLibfabricConnection(const nixlLibfabricConnection &) = delete;
    nixlLibfabricConnection &
    operator=(const nixlLibfabricConnection &) = delete;

    /** Take ownership of the AV entries in rail_remote_addr_list_, inserted by
     *  nixlLibfabricRailManager::insertAllAddresses(). */
    void
    adoptAddresses(std::weak_ptr<nixlLibfabricRailManager *> av_owner);

    /** Drop this connection's references on its AV entries, releasing the EFA address
     *  handles they hold. Runs from the destructor: the connection is shared by every user of
     *  the peer's fi_addrs (remote MDs, posted transfers, queued control messages), so the
     *  last one to let go is the first point at which nothing can still post to them. A
     *  provider releases a removed peer's outstanding operations without completing them, so
     *  removing earlier would leave transfers that never finish. Idempotent. */
    void
    releaseAddresses();

    /** Transition to CONNECTED state. */
    nixl_status_t
    establish();

    /** Transition to DISCONNECTED state. Returns success if already disconnected. */
    nixl_status_t
    disconnect();

    size_t agent_index_; // Unique agent identifier in agent_names vector
    std::string remoteAgent_; // Remote agent name
    std::unordered_map<size_t, std::vector<fi_addr_t>>
        rail_remote_addr_list_; // Rail libfabric addresses. key=rail id.
    std::vector<char *> src_ep_names_; // Rail endpoint names
    std::atomic<ConnectionState> overall_state_; // Current connection state

    // The rail manager whose AVs hold rail_remote_addr_list_. Weak, and expired by the engine
    // at teardown, so a connection that outlives the rails (held by a callback in a request
    // pool, say) leaves the AVs to be closed with them instead of touching freed rails.
    std::weak_ptr<nixlLibfabricRailManager *> av_owner_;

    // Set once the peer holds our endpoints in its AV, so it can attribute our traffic.
    // establishConnection() blocks on handshake_cv_ until this or handshake_rejected_ is set.
    std::atomic<bool> handshake_received_{false};
    // Set when the peer's protocol version is incompatible, so establishConnection() fails with
    // NIXL_ERR_MISMATCH. rejected_peer_proto_ver_ is written under handshake_mutex_ first.
    std::atomic<bool> handshake_rejected_{false};
    uint16_t rejected_peer_proto_ver_ = 0;
    std::mutex handshake_mutex_;
    std::condition_variable handshake_cv_;
};

#endif // NIXL_SRC_PLUGINS_LIBFABRIC_LIBFABRIC_CONNECTION_H
