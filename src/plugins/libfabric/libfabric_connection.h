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

    /** Removes the peer's addresses from every local rail's AV if release_av_ is set (see
     *  releaseAddresses()); otherwise leaves them for the AV to free when it is closed. */
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

    // Whether the destructor may remove this connection's AV entries. Off by default: removing
    // a live peer's entries resets the provider's per-peer message sequence on our side only,
    // and an EFA peer that still holds the old sequence aborts the process when we send to it
    // again. Set only where the peer cannot hold such state for us: it confirmed the close
    // (DISCONNECT_ACK), it is unreachable, or we never sent it anything.
    std::atomic<bool> release_av_{false};

    // Set when the core loaded this peer's connection info (loadRemoteConnInfo from the agent),
    // as opposed to the connection being created from the peer's handshake alone. A peer's
    // DISCONNECT closes only connections the core does not use.
    std::atomic<bool> core_owned_{false};

    // Handshake-advertised state. local_nonce_ identifies this connection in our handshakes and
    // close messages; peer_nonce_ and peer_caps_ come from the peer's latest handshake
    // (0 for a peer that sends none, i.e. an older NIXL).
    const uint64_t local_nonce_;
    std::atomic<uint64_t> peer_nonce_{0};
    std::atomic<uint32_t> peer_caps_{0};

    // Operations in flight to the peer: posted transfers until checkXfer() sees them complete,
    // and queued control sends until their completion. disconnect() waits for zero before it
    // sends DISCONNECT, which must be the last message on this connection.
    std::atomic<int> inflight_{0};

    // Outcome of a DISCONNECT sent on this connection (DisconnectResult), written by the ACK
    // handler or the send's completion and read by disconnect().
    std::atomic<int> close_result_{0};

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

/** Outcome of a DISCONNECT, in nixlLibfabricConnection::close_result_. */
enum DisconnectResult : int {
    NIXL_LIBFABRIC_CLOSE_PENDING = 0,
    NIXL_LIBFABRIC_CLOSE_RELEASED, // Peer removes its entries for us: we may remove ours
    NIXL_LIBFABRIC_CLOSE_KEPT, // Peer keeps its entries for us: we must keep ours
    NIXL_LIBFABRIC_CLOSE_UNREACHABLE, // DISCONNECT could not reach the peer: it is gone
    NIXL_LIBFABRIC_CLOSE_SEND_FAILED, // DISCONNECT failed otherwise: outcome unknown
};

/** Counts one in-flight operation on a connection for as long as it lives, and keeps the
 *  connection, and so its AV entries, alive with it. */
class nixlLibfabricConnPin {
public:
    explicit nixlLibfabricConnPin(std::shared_ptr<nixlLibfabricConnection> conn)
        : conn_(std::move(conn)) {
        conn_->inflight_.fetch_add(1, std::memory_order_acq_rel);
    }

    ~nixlLibfabricConnPin() {
        conn_->inflight_.fetch_sub(1, std::memory_order_acq_rel);
    }

    nixlLibfabricConnPin(const nixlLibfabricConnPin &) = delete;
    nixlLibfabricConnPin &
    operator=(const nixlLibfabricConnPin &) = delete;

private:
    std::shared_ptr<nixlLibfabricConnection> conn_;
};

#endif // NIXL_SRC_PLUGINS_LIBFABRIC_LIBFABRIC_CONNECTION_H
