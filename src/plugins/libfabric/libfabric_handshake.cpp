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
#include "libfabric_backend.h"
#include "serdes/serdes.h"
#include "common/nixl_log.h"

#include <chrono>
#include <cstring>
#include <limits>
#include <thread>

/****************************************
 * Peer-id handshake protocol
 *****************************************/

// Wire format for a handshake message body (serialized via nixlSerDes):
//   "ver"      : uint16 = NIXL_LIBFABRIC_PROTO_VERSION of the sender
//   "name"     : string = agent_name of the SENDER (us). The receiver uses it to find its
//                 connection record for us, so a handshake needs no source-address lookup.
//   "has_conn" : uint8  = 1 if connection info is included, 0 otherwise
//   "conn"     : string = serialized connection info (only if has_conn == 1).
//                 Included when the peer hasn't sent us a handshake yet,
//                 meaning they likely don't have our endpoint addresses.
//   "caps"     : uint32 = NIXL_LIBFABRIC_CAP_* bits of the sender (optional, trailing)
//   "nonce"    : uint64 = the sender's nonce for this connection (optional, trailing)
//
// Receivers read the fields in order and stop after "conn", so older ones ignore "caps" and
// "nonce"; a handshake without them comes from an older peer, which has no capabilities.
//
// Protocol version 1 sent "idx" (the agent index for imm_data) instead of "ver". It is not
// interoperable with version 2, so the version check rejects it at connection setup.
//
// Sized to fit inside one libfabric control buffer
// (NIXL_LIBFABRIC_SEND_RECV_BUFFER_SIZE = 8 KiB).
nixl_status_t
nixlLibfabricEngine::sendHandshakeTo(
    const std::shared_ptr<nixlLibfabricConnection> &conn_ptr) const {
    const nixlLibfabricConnection &conn = *conn_ptr;
    const uint16_t proto_ver = static_cast<uint16_t>(NIXL_LIBFABRIC_PROTO_VERSION);
    const std::string &my_name = localAgent;

    // Include connection info if peer hasn't sent us a handshake yet (meaning
    // they likely don't have our connection info to create a connection).
    std::string piggybacked_conn_info;
    if (!conn.handshake_received_.load(std::memory_order_acquire)) {
        nixl_status_t ci_status = getConnInfo(piggybacked_conn_info);
        if (ci_status != NIXL_SUCCESS) {
            NIXL_ERROR << "getConnInfo failed in sendHandshakeTo for '" << conn.remoteAgent_
                       << "': status=" << ci_status;
            return ci_status;
        }
    }

    nixlSerDes sd;
    sd.addBuf(NIXL_HANDSHAKE_TAG_VER, &proto_ver, sizeof(proto_ver));
    sd.addStr(NIXL_HANDSHAKE_TAG_NAME, my_name);
    uint8_t has_conn = piggybacked_conn_info.empty() ? 0 : 1;
    sd.addBuf(NIXL_HANDSHAKE_TAG_HAS_CONN, &has_conn, sizeof(has_conn));
    if (has_conn) {
        sd.addStr(NIXL_HANDSHAKE_TAG_CONN, piggybacked_conn_info);
    }
    const uint32_t caps = NIXL_LIBFABRIC_LOCAL_CAPS;
    sd.addBuf(NIXL_HANDSHAKE_TAG_CAPS, &caps, sizeof(caps));
    sd.addBuf(NIXL_HANDSHAKE_TAG_NONCE, &conn.local_nonce_, sizeof(conn.local_nonce_));
    std::string payload = sd.exportStr();

    if (payload.size() > NIXL_LIBFABRIC_SEND_RECV_BUFFER_SIZE) {
        NIXL_ERROR << "Handshake payload too large (" << payload.size() << " bytes) — agent_name='"
                   << my_name << "'";
        return NIXL_ERR_BACKEND;
    }

    constexpr size_t kRailId = 0;
    auto rail_it = conn.rail_remote_addr_list_.find(kRailId);
    if (rail_it == conn.rail_remote_addr_list_.end() || rail_it->second.empty()) {
        NIXL_WARN << "No remote rail addresses on record for '" << conn.remoteAgent_
                  << "'; cannot send handshake";
        return NIXL_ERR_BACKEND;
    }
    nixlLibfabricReq *req = rail_manager_.getRail(kRailId).allocateControlRequest(
        payload.size(), LibfabricUtils::getNextXferId());
    if (!req) {
        NIXL_ERROR << "Failed to allocate control request for handshake to '" << conn.remoteAgent_
                   << "'";
        return NIXL_ERR_BACKEND;
    }

    std::memcpy(req->buffer, payload.data(), payload.size());
    req->buffer_size = payload.size();

    NIXL_DEBUG << "Sending handshake to '" << conn.remoteAgent_ << "' proto_ver=" << proto_ver
               << " (my agent_name='" << my_name
               << "', piggybacked_conn_info_len=" << piggybacked_conn_info.size() << ")";
    // The callback keeps the peer's AV entry alive, and the send counted as in flight, until it
    // completes.
    return rail_manager_.postControlMessage(
        nixlLibfabricRailManager::ControlMessageType::HANDSHAKE,
        req,
        rail_it->second[0],
        [pin = std::make_shared<nixlLibfabricConnPin>(conn_ptr)](nixl_status_t) {});
}

void
nixlLibfabricEngine::rejectHandshake(const std::string &peer_agent_name, uint16_t peer_proto_ver) {
    std::shared_ptr<nixlLibfabricConnection> conn;
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        auto it = connections_.find(peer_agent_name);
        if (it != connections_.end() && it->second) {
            conn = it->second;
        }
    }

    if (!conn) {
        // Not registered yet: createAgentConnection applies it, like a buffered handshake.
        // The piggybacked connection info of an incompatible peer is deliberately not loaded.
        std::lock_guard<std::mutex> plk(pending_handshake_mutex_);
        pending_rejected_handshakes_[peer_agent_name] = peer_proto_ver;
        return;
    }

    {
        std::lock_guard<std::mutex> hlk(conn->handshake_mutex_);
        conn->rejected_peer_proto_ver_ = peer_proto_ver;
        conn->handshake_rejected_.store(true, std::memory_order_release);
    }
    conn->handshake_cv_.notify_all();
}

void
nixlLibfabricEngine::handleHandshake(const std::string &raw_payload) {
    // Decode and validate the handshake wire format.
    nixlSerDes sd;
    if (sd.importStr(raw_payload) != NIXL_SUCCESS) {
        NIXL_ERROR << "Failed to deserialize handshake payload";
        return;
    }

    // nixlSerDes reads fields in order. A version-1 peer sends "idx" where we send "ver", so
    // consume either one, then "name", to identify the peer before rejecting it.
    uint16_t peer_proto_ver = 0;
    if (sd.getBuf(NIXL_HANDSHAKE_TAG_VER, &peer_proto_ver, sizeof(peer_proto_ver)) !=
        NIXL_SUCCESS) {
        uint16_t v1_idx = 0;
        if (sd.getBuf(NIXL_HANDSHAKE_TAG_V1_IDX, &v1_idx, sizeof(v1_idx)) != NIXL_SUCCESS) {
            NIXL_ERROR << "Handshake has neither a '" << NIXL_HANDSHAKE_TAG_VER << "' nor an '"
                       << NIXL_HANDSHAKE_TAG_V1_IDX << "' field; dropping it";
            return;
        }
        peer_proto_ver = 1;
    }
    std::string peer_agent_name = sd.getStr(NIXL_HANDSHAKE_TAG_NAME);
    if (peer_agent_name.empty()) {
        NIXL_ERROR << "Handshake missing or empty 'name' field";
        return;
    }
    if (peer_proto_ver != NIXL_LIBFABRIC_PROTO_VERSION) {
        NIXL_ERROR << "Handshake from '" << peer_agent_name << "' speaks libfabric-plugin protocol "
                   << "version " << peer_proto_ver << ", which is not interoperable with version "
                   << NIXL_LIBFABRIC_PROTO_VERSION
                   << ". Upgrade both ends of the cluster to the same NIXL version.";
        rejectHandshake(peer_agent_name, peer_proto_ver);
        return;
    }
    uint8_t has_conn = 0;
    if (sd.getBuf(NIXL_HANDSHAKE_TAG_HAS_CONN, &has_conn, sizeof(has_conn)) != NIXL_SUCCESS) {
        NIXL_ERROR << "Handshake missing 'has_conn' field";
        return;
    }
    // The handshake may optionally carry the sender's connection info, for peers that
    // haven't had their connection info loaded via loadRemoteConnInfo() yet.
    std::string piggybacked_conn_info;
    if (has_conn) {
        piggybacked_conn_info = sd.getStr(NIXL_HANDSHAKE_TAG_CONN);
        if (piggybacked_conn_info.empty()) {
            NIXL_ERROR << "Handshake has_conn=1 but 'conn' field is empty";
            return;
        }
    }

    // Optional trailing fields (see the wire format above). Absent from older peers.
    uint32_t peer_caps = 0;
    uint64_t peer_nonce = 0;
    if (sd.peekBufLen(NIXL_HANDSHAKE_TAG_CAPS) == sizeof(peer_caps)) {
        sd.getBuf(NIXL_HANDSHAKE_TAG_CAPS, &peer_caps, sizeof(peer_caps));
        if (sd.peekBufLen(NIXL_HANDSHAKE_TAG_NONCE) == sizeof(peer_nonce)) {
            sd.getBuf(NIXL_HANDSHAKE_TAG_NONCE, &peer_nonce, sizeof(peer_nonce));
        }
    }

    NIXL_DEBUG << "Received handshake from peer '" << peer_agent_name
               << "' proto_ver=" << peer_proto_ver
               << " piggybacked_conn_info_len=" << piggybacked_conn_info.size()
               << " caps=0x" << std::hex << peer_caps << std::dec;

    // Process the decoded handshake.
    std::shared_ptr<nixlLibfabricConnection> conn;
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        auto it = connections_.find(peer_agent_name);
        if (it != connections_.end() && it->second) {
            conn = it->second;
        }
    }

    if (!conn) {
        {
            std::lock_guard<std::mutex> plk(pending_handshake_mutex_);
            pending_inbound_handshakes_[peer_agent_name] = {peer_caps, peer_nonce};
            NIXL_DEBUG << "Buffered handshake from not-yet-known peer '" << peer_agent_name
                       << "'; will apply on createAgentConnection";
        }

        if (piggybacked_conn_info.empty()) {
            // Code should not reach here. When piggybacked_conn_info is empty, the handshake
            // source should have received a handshake message from this side, which means
            // a connection ('conn' above) should have been created.
            NIXL_ERROR << "Connection not found for peer agent: " << peer_agent_name
                       << ", and no piggybacked_conn_info provided in handshake";
            return;
        } else {
            nixl_status_t load_status = this->loadRemoteConnInfoImpl(
                peer_agent_name, piggybacked_conn_info, /*from_core=*/false);
            if (load_status != NIXL_SUCCESS) {
                NIXL_ERROR << "Failed to loadRemoteConnInfo() received with handshake. "
                           << "peer agent: " << peer_agent_name
                           << ", piggybacked_conn_info size: " << piggybacked_conn_info.size();
            }
            return; // loadRemoteConnInfo will take care of draining the
                    // buffered handshake as part of connection creation.
        }
    } else {
        // A re-handshake can come from a new connection on the peer's side: track its nonce.
        conn->peer_caps_.store(peer_caps, std::memory_order_release);
        conn->peer_nonce_.store(peer_nonce, std::memory_order_release);
        {
            std::lock_guard<std::mutex> hlk(conn->handshake_mutex_);
            conn->handshake_received_.store(true, std::memory_order_release);
        }
        conn->handshake_cv_.notify_all();
        NIXL_INFO << "Handshake stored: peer='" << peer_agent_name
                  << "' — it has our endpoints in its address vectors, so it can attribute "
                     "our transfers and we may start sending";

        if (has_conn) {
            // The sender has not received our handshake yet (see sendHandshakeTo), so it
            // is establishing fresh: rebuilt its side, or both sides race first-time
            // setup. The has_conn=0 reply cannot loop and goes to the addresses on record.
            if (peer_agent_name == localAgent) {
                return; // we never handshake ourselves (mirrors loadRemoteConnInfo)
            }
            auto rail_it = conn->rail_remote_addr_list_.find(0);
            if (rail_it == conn->rail_remote_addr_list_.end() || rail_it->second.empty()) {
                NIXL_WARN << "Cannot reply to re-establishment handshake from '" << peer_agent_name
                          << "': no remote rail addresses on record";
                return;
            }
            NIXL_INFO << "Peer '" << peer_agent_name
                      << "' re-established its side; replying so its handshake wait completes";
            if (progress_thread_enabled_) {
                // handleHandshake runs on the progress thread here, and postSend()
                // retries FI_EAGAIN without draining its own completions when the
                // progress thread owns them — an inline reply could wedge the only
                // thread that can make progress. Hand the reply to the CM thread.
                queueHandshakeReply(conn);
            } else {
                nixl_status_t status = sendHandshakeTo(conn);
                if (status != NIXL_SUCCESS) {
                    NIXL_WARN << "Replying to re-establishment handshake from '" << peer_agent_name
                              << "' failed (non-fatal; re-triggers on the peer's next re-add): "
                                 "status="
                              << status;
                }
            }
        }
    }
}

void
nixlLibfabricEngine::queueHandshakeReply(std::shared_ptr<nixlLibfabricConnection> conn) {
    {
        const std::lock_guard<std::mutex> lock(cm_mutex_);
        if (cm_thread_stop_) {
            return; // engine teardown; the peer's next re-add re-triggers the reply
        }
        pending_replies_.push_back(std::move(conn));
        ensureCmThreadLocked();
    }
    cm_cv_.notify_one();
}

void
nixlLibfabricEngine::ensureCmThreadLocked() {
    if (!cm_thread_.joinable()) {
        cm_thread_ = std::thread(&nixlLibfabricEngine::cmThread, this);
    }
}

void
nixlLibfabricEngine::queueCmTask(std::function<void()> task) {
    {
        const std::lock_guard<std::mutex> lock(cm_mutex_);
        if (cm_thread_stop_) {
            return;
        }
        pending_cm_tasks_.push_back(std::move(task));
        ensureCmThreadLocked();
    }
    cm_cv_.notify_one();
}

void
nixlLibfabricEngine::sendHandshakeReply(const std::shared_ptr<nixlLibfabricConnection> &conn) {
    // DISCONNECTED is also the pre-connect state of a live registration, so the
    // state cannot decide this: only a registration that is gone (disconnect()
    // removes it) means no reply. An unconnected holder still owes one — nothing
    // else completes the re-establishing peer's wait.
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        auto it = connections_.find(conn->remoteAgent_);
        if (it == connections_.end() || it->second != conn) {
            NIXL_DEBUG << "Skipping re-establishment reply to '" << conn->remoteAgent_
                       << "': connection no longer registered";
            return;
        }
    }
    nixl_status_t status = sendHandshakeTo(conn);
    if (status != NIXL_SUCCESS) {
        NIXL_WARN << "Replying to re-establishment handshake from '" << conn->remoteAgent_
                  << "' failed (non-fatal; re-triggers on the peer's next re-add): status="
                  << status;
    }
}

void
nixlLibfabricEngine::cmThread() {
    // Wakes at least this often to release connections whose grace period has passed.
    constexpr auto kTick = std::chrono::milliseconds(20);
    while (true) {
        std::shared_ptr<nixlLibfabricConnection> reply;
        std::deque<std::function<void()>> tasks;
        std::vector<std::shared_ptr<nixlLibfabricConnection>> due;
        {
            std::unique_lock<std::mutex> lock(cm_mutex_);
            cm_cv_.wait_for(lock, kTick, [this]() {
                return cm_thread_stop_ || !pending_replies_.empty() || !pending_cm_tasks_.empty();
            });
            if (cm_thread_stop_) {
                return; // queued work is dropped: teardown makes it moot
            }
            if (!pending_replies_.empty()) {
                reply = std::move(pending_replies_.front());
                pending_replies_.pop_front();
            }
            tasks.swap(pending_cm_tasks_);
            const auto now = std::chrono::steady_clock::now();
            std::erase_if(deferred_releases_, [&](const DeferredRelease &d) {
                if (now < d.not_before ||
                    d.conn->inflight_.load(std::memory_order_acquire) != 0) {
                    return false;
                }
                due.push_back(d.conn);
                return true;
            });
        }
        for (auto &task : tasks) {
            task();
        }
        for (auto &conn : due) {
            releasePeer(conn);
        }
        if (reply) {
            sendHandshakeReply(reply);
        }
    }
}

/****************************************
 * Mutual connection close
 *****************************************/

// Removing a live peer's AV entries is only safe when the peer removes its entries for us too.
// The EFA provider numbers the messages of each (local endpoint, remote endpoint) pair. Removing
// an entry drops that numbering on one side; once the address is inserted again, sends restart at
// zero, and a peer that still holds the old numbering takes them as already processed, which the
// provider reports through the EQ and, with no EQ bound, by aborting the process. So a close is
// an exchange on rail 0: DISCONNECT, the last message the closer sends, answered by
// DISCONNECT_ACK, the last message the peer sends. Each side then removes its entries, and a
// re-add of the same peer waits out a cooldown so the peer has removed its own first.

nixl_status_t
nixlLibfabricEngine::sendDisconnectMessage(const std::shared_ptr<nixlLibfabricConnection> &conn,
                                           bool ack,
                                           uint8_t status,
                                           std::function<void(nixl_status_t)> on_complete) const {
    constexpr size_t kRailId = 0;
    auto rail_it = conn->rail_remote_addr_list_.find(kRailId);
    if (rail_it == conn->rail_remote_addr_list_.end() || rail_it->second.empty()) {
        NIXL_WARN << "No remote rail addresses on record for '" << conn->remoteAgent_
                  << "'; cannot send " << (ack ? "DISCONNECT_ACK" : "DISCONNECT");
        return NIXL_ERR_BACKEND;
    }

    DisconnectPayload header{};
    header.sender_nonce = conn->local_nonce_;
    header.receiver_nonce = conn->peer_nonce_.load(std::memory_order_acquire);
    header.status = status;
    const size_t size = sizeof(header) + localAgent.size();
    if (size > NIXL_LIBFABRIC_SEND_RECV_BUFFER_SIZE) {
        NIXL_ERROR << "Agent name too long for a disconnect message";
        return NIXL_ERR_BACKEND;
    }

    nixlLibfabricReq *req = rail_manager_.getRail(kRailId).allocateControlRequest(
        size, LibfabricUtils::getNextXferId());
    if (!req) {
        NIXL_ERROR << "Failed to allocate control request for disconnect message to '"
                   << conn->remoteAgent_ << "'";
        return NIXL_ERR_BACKEND;
    }
    std::memcpy(req->buffer, &header, sizeof(header));
    std::memcpy(static_cast<char *>(req->buffer) + sizeof(header), localAgent.data(),
                localAgent.size());
    req->buffer_size = size;

    NIXL_DEBUG << "Sending " << (ack ? "DISCONNECT_ACK" : "DISCONNECT") << " to '"
               << conn->remoteAgent_ << "' status=" << static_cast<int>(status);
    nixl_status_t ret = rail_manager_.postControlMessage(
        ack ? nixlLibfabricRailManager::ControlMessageType::DISCONNECT_ACK :
              nixlLibfabricRailManager::ControlMessageType::DISCONNECT,
        req,
        rail_it->second[0],
        [pin = std::make_shared<nixlLibfabricConnPin>(conn),
         on_complete = std::move(on_complete)](nixl_status_t send_status) {
            if (on_complete) {
                on_complete(send_status);
            }
        });
    // No progress here: this also runs from a receive completion (the ACK without a progress
    // thread). Waiters in closeConnection() progress the rails themselves.
    return ret;
}

bool
nixlLibfabricEngine::waitWithProgress(const std::function<bool()> &done,
                                      std::chrono::milliseconds timeout) const {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        if (!progress_thread_enabled_) {
            // Without a progress thread nothing else reaps our completions while we wait.
            rail_manager_.progressActiveRails(
                nixlLibfabricRailManager::ProgressCudaDevice::SetAndRestore);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

void
nixlLibfabricEngine::scheduleRelease(const std::shared_ptr<nixlLibfabricConnection> &conn) {
    conn->release_av_.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        av_tombstones_[conn->remoteAgent_] = std::chrono::steady_clock::now();
    }
    {
        const std::lock_guard<std::mutex> lock(cm_mutex_);
        if (cm_thread_stop_) {
            return; // teardown: the closing AVs free the entries
        }
        deferred_releases_.push_back(
            {conn, std::chrono::steady_clock::now() + av_release_grace_});
        ensureCmThreadLocked();
    }
    cm_cv_.notify_one();
}

void
nixlLibfabricEngine::releasePeer(const std::shared_ptr<nixlLibfabricConnection> &conn) {
    conn->releaseAddresses();
    // Anything still waiting on this peer's writes or fragments can never complete now.
    const uint64_t idx = conn->agent_index_;
    size_t purged = 0;
    {
        std::lock_guard<std::mutex> lock(receiver_tracking_mutex_);
        purged = std::erase_if(pending_notifications_,
                               [idx](const auto &kv) { return (kv.first >> 16) == idx; });
    }
    if (purged) {
        NIXL_WARN << "Dropped " << purged << " incomplete notification(s) from closed peer '"
                  << conn->remoteAgent_ << "'";
    }
}

void
nixlLibfabricEngine::flushPendingRelease(const std::string &agent_name) {
    std::vector<std::shared_ptr<nixlLibfabricConnection>> due;
    {
        const std::lock_guard<std::mutex> lock(cm_mutex_);
        std::erase_if(deferred_releases_, [&](const DeferredRelease &d) {
            if (d.conn->remoteAgent_ != agent_name ||
                d.conn->inflight_.load(std::memory_order_acquire) != 0) {
                return false;
            }
            due.push_back(d.conn);
            return true;
        });
    }
    for (auto &conn : due) {
        releasePeer(conn);
    }
}

void
nixlLibfabricEngine::waitOutReinsertCooldown(const std::string &agent_name) {
    std::chrono::steady_clock::time_point closed_at;
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        auto it = av_tombstones_.find(agent_name);
        if (it == av_tombstones_.end()) {
            return;
        }
        closed_at = it->second;
        const auto now = std::chrono::steady_clock::now();
        // Forget tombstones that can no longer delay anyone.
        std::erase_if(av_tombstones_, [&](const auto &kv) {
            return now - kv.second > av_reinsert_cooldown_;
        });
    }
    const auto ready_at = closed_at + av_reinsert_cooldown_;
    const auto now = std::chrono::steady_clock::now();
    if (now < ready_at) {
        NIXL_INFO << "Re-adding '" << agent_name << "' "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(ready_at - now).count()
                  << " ms after closing it; waiting out the AV re-insert cooldown so the peer has "
                     "removed its entries for us";
        std::this_thread::sleep_for(ready_at - now);
    }
    // Our own old entries must be gone too, or the insert would reuse them.
    flushPendingRelease(agent_name);
}

void
nixlLibfabricEngine::closeConnection(const std::shared_ptr<nixlLibfabricConnection> &conn) {
    const std::string &name = conn->remoteAgent_;
    if (!(conn->peer_caps_.load(std::memory_order_acquire) & NIXL_LIBFABRIC_CAP_DISCONNECT)) {
        NIXL_INFO << "Keeping the AV entries of '" << name
                  << "': the peer runs a NIXL that cannot close connections mutually";
        return;
    }

    auto linger = [this, &conn](const char *why) {
        NIXL_WARN << "Keeping the AV entries of '" << conn->remoteAgent_ << "': " << why;
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        lingering_.emplace(conn->remoteAgent_, conn);
    };

    // DISCONNECT must be the last message to the peer, so wait for everything in flight.
    if (!waitWithProgress(
            [&conn] { return conn->inflight_.load(std::memory_order_acquire) == 0; },
            disconnect_timeout_)) {
        linger("operations to the peer were still in flight at disconnect");
        return;
    }

    conn->close_result_.store(NIXL_LIBFABRIC_CLOSE_PENDING, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        closing_[name] = conn;
    }
    std::weak_ptr<nixlLibfabricConnection> weak = conn;
    nixl_status_t status =
        sendDisconnectMessage(conn, /*ack=*/false, 0, [weak](nixl_status_t send_status) {
            auto c = weak.lock();
            if (!c || send_status == NIXL_SUCCESS) {
                return;
            }
            int expected = NIXL_LIBFABRIC_CLOSE_PENDING;
            c->close_result_.compare_exchange_strong(
                expected,
                send_status == NIXL_ERR_REMOTE_DISCONNECT ? NIXL_LIBFABRIC_CLOSE_UNREACHABLE :
                                                            NIXL_LIBFABRIC_CLOSE_SEND_FAILED);
        });
    if (status == NIXL_SUCCESS) {
        waitWithProgress(
            [&conn] {
                return conn->close_result_.load(std::memory_order_acquire) !=
                    NIXL_LIBFABRIC_CLOSE_PENDING;
            },
            disconnect_timeout_);
    }
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        auto it = closing_.find(name);
        if (it != closing_.end() && it->second == conn) {
            closing_.erase(it);
        }
    }

    switch (status == NIXL_SUCCESS ? conn->close_result_.load(std::memory_order_acquire) :
                                     static_cast<int>(NIXL_LIBFABRIC_CLOSE_SEND_FAILED)) {
    case NIXL_LIBFABRIC_CLOSE_RELEASED:
        NIXL_INFO << "Closed the connection to '" << name << "' on both sides";
        scheduleRelease(conn);
        break;
    case NIXL_LIBFABRIC_CLOSE_UNREACHABLE:
        NIXL_INFO << "'" << name << "' is unreachable; removing its AV entries";
        scheduleRelease(conn);
        break;
    case NIXL_LIBFABRIC_CLOSE_KEPT:
        linger("the peer still uses its connection to us");
        break;
    case NIXL_LIBFABRIC_CLOSE_PENDING:
        linger("no DISCONNECT_ACK before the timeout");
        break;
    default:
        linger("sending DISCONNECT failed");
        break;
    }
}

void
nixlLibfabricEngine::handleDisconnectMessage(uint64_t msg_type,
                                             const std::string &raw_payload,
                                             uint32_t sender_peer_idx) {
    DisconnectPayload header;
    std::memcpy(&header, raw_payload.data(), sizeof(header));
    const std::string name = raw_payload.substr(sizeof(header));
    const bool is_ack = (msg_type == NIXL_LIBFABRIC_MSG_DISCONNECT_ACK);

    auto matches = [&](const std::shared_ptr<nixlLibfabricConnection> &c) {
        return c && c->remoteAgent_ == name && c->local_nonce_ == header.receiver_nonce &&
            c->peer_nonce_.load(std::memory_order_acquire) == header.sender_nonce;
    };

    enum class Found { NONE, ACTIVE, CLOSING, LINGERING } found = Found::NONE;
    std::shared_ptr<nixlLibfabricConnection> conn;
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        // The source address must belong to the agent the message names.
        if (sender_peer_idx >= agent_names_.size() || agent_names_[sender_peer_idx] != name) {
            NIXL_WARN << "Dropping " << (is_ack ? "DISCONNECT_ACK" : "DISCONNECT")
                      << " that names '" << name << "' from another sender";
            return;
        }
        if (auto it = closing_.find(name); it != closing_.end() && matches(it->second)) {
            conn = it->second;
            found = Found::CLOSING;
        } else if (!is_ack) {
            if (auto ait = connections_.find(name);
                ait != connections_.end() && matches(ait->second)) {
                conn = ait->second;
                found = Found::ACTIVE;
            } else {
                auto [lo, hi] = lingering_.equal_range(name);
                for (auto lit = lo; lit != hi; ++lit) {
                    if (matches(lit->second)) {
                        conn = lit->second;
                        found = Found::LINGERING;
                        lingering_.erase(lit);
                        break;
                    }
                }
            }
        }
    }

    if (found == Found::NONE) {
        // The sender times out and keeps its entries, which is safe.
        NIXL_DEBUG << "Ignoring " << (is_ack ? "DISCONNECT_ACK" : "DISCONNECT") << " from '"
                   << name << "' for a connection we no longer have";
        return;
    }

    if (is_ack) {
        conn->close_result_.store(header.status == NIXL_LIBFABRIC_DISCONNECT_KEPT ?
                                      NIXL_LIBFABRIC_CLOSE_KEPT :
                                      NIXL_LIBFABRIC_CLOSE_RELEASED,
                                  std::memory_order_release);
        return;
    }

    uint8_t reply = NIXL_LIBFABRIC_DISCONNECT_RELEASED;
    switch (found) {
    case Found::ACTIVE:
        if (conn->core_owned_.load(std::memory_order_acquire)) {
            // Our core still uses this peer; it closes the connection itself when it invalidates
            // the peer, and until then both sides keep their entries.
            reply = NIXL_LIBFABRIC_DISCONNECT_KEPT;
        } else {
            NIXL_INFO << "'" << name << "' closed its connection to us; closing ours";
            conn->disconnect();
            retireConnection(conn);
        }
        break;
    case Found::CLOSING:
        // Both sides are closing at once: each answers the other, and both remove.
        conn->close_result_.store(NIXL_LIBFABRIC_CLOSE_RELEASED, std::memory_order_release);
        break;
    case Found::LINGERING:
        NIXL_INFO << "'" << name << "' closed the connection we had kept; removing its entries";
        break;
    default:
        break;
    }

    auto send_ack = [this, conn, reply, found]() {
        // The ACK is our last message to the peer; the release waits for its completion (the
        // send pins the connection) and for the grace period.
        nixl_status_t status = sendDisconnectMessage(conn, /*ack=*/true, reply, nullptr);
        if (status != NIXL_SUCCESS) {
            NIXL_WARN << "Sending DISCONNECT_ACK to '" << conn->remoteAgent_
                      << "' failed with status " << status << "; keeping its AV entries";
            if (found != Found::CLOSING && reply == NIXL_LIBFABRIC_DISCONNECT_RELEASED) {
                std::lock_guard<std::mutex> lock(connection_state_mutex_);
                lingering_.emplace(conn->remoteAgent_, conn);
            }
            return;
        }
        if (reply == NIXL_LIBFABRIC_DISCONNECT_RELEASED && found != Found::CLOSING) {
            scheduleRelease(conn); // the closing side's disconnect() schedules its own
        }
    };
    if (progress_thread_enabled_) {
        // This runs on the progress thread, which must not post from its completion context.
        queueCmTask(std::move(send_ack));
    } else {
        send_ack();
    }
}
