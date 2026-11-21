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
#include "libfabric_connection.h"
#include "common/nixl_log.h"
#include "libfabric/libfabric_rail_manager.h"

#include <random>

namespace {
uint64_t
makeNonce() {
    std::random_device rd;
    uint64_t nonce = 0;
    while (nonce == 0) { // 0 means "no nonce" on the wire
        nonce = (static_cast<uint64_t>(rd()) << 32) | rd();
    }
    return nonce;
}
} // namespace

nixlLibfabricConnection::nixlLibfabricConnection(const std::string &remote_agent,
                                                 size_t agent_index)
    : agent_index_(agent_index),
      remoteAgent_(remote_agent),
      overall_state_(ConnectionState::DISCONNECTED),
      local_nonce_(makeNonce()) {}

nixlLibfabricConnection::~nixlLibfabricConnection() {
    if (release_av_.load(std::memory_order_acquire)) {
        releaseAddresses();
    } else if (!av_owner_.expired()) {
        NIXL_DEBUG << "Keeping the AV entries of agent " << remoteAgent_
                   << ": the peer did not confirm a mutual close";
    }
}

void
nixlLibfabricConnection::adoptAddresses(std::weak_ptr<nixlLibfabricRailManager *> av_owner) {
    av_owner_ = std::move(av_owner);
}

void
nixlLibfabricConnection::releaseAddresses() {
    const std::shared_ptr<nixlLibfabricRailManager *> owner = av_owner_.lock();
    av_owner_.reset();
    if (!owner || !*owner) {
        return;
    }

    size_t count = 0;
    for (const auto &[rail_id, addrs] : rail_remote_addr_list_) {
        count += addrs.size();
    }
    const nixl_status_t status = (*owner)->removeAllAddresses(rail_remote_addr_list_);
    if (status != NIXL_SUCCESS) {
        NIXL_WARN << "Releasing the " << count << " AV entries of agent " << remoteAgent_
                  << " failed partway with status " << status;
        return;
    }
    NIXL_INFO << "Released the " << count << " AV entries of agent " << remoteAgent_;
}

nixl_status_t
nixlLibfabricConnection::establish() {
    if (overall_state_.load(std::memory_order_acquire) == ConnectionState::CONNECTED) {
        NIXL_DEBUG << "Connection already established for " << remoteAgent_;
        return NIXL_SUCCESS;
    }

    NIXL_DEBUG << "Establishing rail connections for agent: " << remoteAgent_;
    NIXL_DEBUG << "Using connection info with " << src_ep_names_.size() << " rails";
    for (size_t i = 0; i < src_ep_names_.size(); ++i) {
        NIXL_DEBUG << "Rail " << i << ": "
                   << LibfabricUtils::hexdump(src_ep_names_[i], LF_EP_NAME_MAX_LEN);
    }
    NIXL_DEBUG << "Agent index: " << agent_index_;

    overall_state_.store(ConnectionState::CONNECTED, std::memory_order_release);
    NIXL_INFO << "Connection state for agent " << remoteAgent_ << " is now CONNECTED";

    return NIXL_SUCCESS;
}

nixl_status_t
nixlLibfabricConnection::disconnect() {
    if (overall_state_.load(std::memory_order_acquire) == ConnectionState::DISCONNECTED) {
        NIXL_DEBUG << "Connection already disconnected for " << remoteAgent_;
        return NIXL_SUCCESS;
    }

    // The AV entries are released with the last reference to this connection, once nothing in
    // flight can still use them (see releaseAddresses()).
    overall_state_.store(ConnectionState::DISCONNECTED, std::memory_order_release);
    NIXL_INFO << "Disconnected from agent: " << remoteAgent_;
    return NIXL_SUCCESS;
}
