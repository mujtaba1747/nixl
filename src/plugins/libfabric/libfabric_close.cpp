/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 Amazon.com, Inc. and affiliates.
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

#include <cstring>
#include <thread>
#include <vector>

/****************************************
 * Connection close exchange
 *****************************************/

// When the last user of a connection lets go (disconnect(), a failed load, or a peer's CLOSE
// for a connection only its handshake created), its AV entries are handed to a ClosingPeer
// record instead of being removed, and the two sides agree on what happens to them:
//
//   A (connection released)                 B (peer)
//   CLOSE {name}               ---------->  connection loaded by B's core: keep it
//                              <----------  CLOSE_ACK {name, kept=1}   -> A keeps (PARKED)
//                                           connection created by A's handshake only: retire
//                                           it; once nothing uses it any more:
//                              <----------  CLOSE_ACK {name, kept=0}   -> B removes when sent
//   A removes on receipt
//
// - A CLOSE that cannot be delivered means the peer is gone, so the entries are removed.
// - A CLOSE that gets no answer within close_timeout_ms (a peer that predates the exchange,
//   or is stuck) leaves the entries PARKED: removing them on one side only is unsafe.
// - A parked peer is closed later by the other side's own CLOSE, which is then answered with
//   kept=0, and a parked peer that is re-added simply keeps using its entries.
// - Both sides may release at once; each then answers the other's CLOSE and removes once its
//   answer is sent.
// - A peer whose entries were removed is re-added from the core only after the exchange is
//   over and reinsert_cooldown_ms has passed, so the peer has removed its own.
//
// Both messages go on rail 0 and are attributed by source address, so only a peer we hold in
// our AV can close our entries for it, and only those. Payload (nixlSerDes):
//   "name" : string = agent name of the sender
//   "kept" : uint8  = CLOSE_ACK only: 1 if the sender keeps its entries for us

namespace {
using Clock = std::chrono::steady_clock;
using CtrlType = nixlLibfabricRailManager::ControlMessageType;

size_t
countAddrs(const std::unordered_map<size_t, std::vector<fi_addr_t>> &addrs) {
    size_t n = 0;
    for (const auto &[rail, list] : addrs) {
        n += list.size();
    }
    return n;
}
} // namespace

void
nixlLibfabricEngine::initCloseExchange() {
    size_t value = static_cast<size_t>(close_timeout_.count());
    LibfabricUtils::getCustomIntParam(getCustomParams(), "close_timeout_ms", value);
    close_timeout_ = std::chrono::milliseconds(value);
    value = static_cast<size_t>(reinsert_cooldown_.count());
    LibfabricUtils::getCustomIntParam(getCustomParams(), "reinsert_cooldown_ms", value);
    reinsert_cooldown_ = std::chrono::milliseconds(value);
    NIXL_DEBUG << "Close exchange: close_timeout_ms=" << close_timeout_.count()
               << " reinsert_cooldown_ms=" << reinsert_cooldown_.count();

    release_hook_ = std::make_shared<nixlLibfabricReleaseHook>(
        [this](nixlLibfabricConnection &conn) { return onConnectionReleased(conn); });
    rail_manager_.getRail(0).setCloseCallback(
        [this](uint64_t msg_type, const std::string &payload, uint32_t sender_idx) {
            handleCloseMessage(msg_type, payload, sender_idx);
        });
}

void
nixlLibfabricEngine::queueCmTask(std::function<void()> task) {
    {
        const std::lock_guard<std::mutex> lock(cm_mutex_);
        if (cm_thread_stop_) {
            return; // teardown: closing the AVs frees every entry
        }
        cm_tasks_.push_back(std::move(task));
        if (!cm_thread_.joinable()) {
            cm_thread_ = std::thread(&nixlLibfabricEngine::cmThread, this);
        }
    }
    cm_cv_.notify_one();
}

nixl_status_t
nixlLibfabricEngine::sendCloseMessage(CtrlType type,
                                      fi_addr_t dest,
                                      bool kept,
                                      std::function<void(nixl_status_t)> on_complete) const {
    nixlSerDes sd;
    sd.addStr(NIXL_CLOSE_TAG_NAME, localAgent);
    if (type == CtrlType::CLOSE_ACK) {
        const uint8_t kept_byte = kept ? 1 : 0;
        sd.addBuf(NIXL_CLOSE_TAG_KEPT, &kept_byte, sizeof(kept_byte));
    }
    const std::string payload = sd.exportStr();

    nixlLibfabricReq *req = rail_manager_.getRail(0).allocateControlRequest(
        payload.size(), LibfabricUtils::getNextXferId());
    if (!req) {
        NIXL_ERROR << "Failed to allocate a control request for a close message";
        return NIXL_ERR_BACKEND;
    }
    std::memcpy(req->buffer, payload.data(), payload.size());
    req->buffer_size = payload.size();
    return rail_manager_.postControlMessage(type, req, dest, std::move(on_complete));
}

bool
nixlLibfabricEngine::onConnectionReleased(nixlLibfabricConnection &conn) {
    if (conn.remoteAgent_ == localAgent) {
        return false; // the self-connection has no peer to agree with
    }
    auto rail0 = conn.rail_remote_addr_list_.find(0);
    if (rail0 == conn.rail_remote_addr_list_.end() || rail0->second.empty()) {
        return false; // no control path to the peer
    }

    auto rec = std::make_shared<ClosingPeer>();
    rec->name = conn.remoteAgent_;
    rec->agent_idx = static_cast<uint32_t>(conn.agent_index_);
    rec->ctrl_addr = rail0->second[0];
    rec->addrs = std::move(conn.rail_remote_addr_list_);
    conn.rail_remote_addr_list_.clear();
    const bool answer = conn.peer_closed_.load(std::memory_order_acquire);
    rec->state = answer ? ClosingPeer::State::ACKING : ClosingPeer::State::AWAIT_ACK;
    rec->deadline = Clock::now() + close_timeout_;

    std::shared_ptr<ClosingPeer> displaced;
    {
        const std::lock_guard<std::mutex> lock(close_mutex_);
        auto &slot = closing_[rec->name];
        displaced = std::move(slot);
        slot = rec;
    }
    if (displaced) {
        // absorbClose() consumes a record whenever the peer is re-added, so this is a second
        // connection to the same agent name. Its references are no longer needed by anyone
        // (a REMOVING record's are being dropped on the CM thread already).
        NIXL_WARN << "Dropping an earlier close record for agent " << rec->name;
        close_cv_.notify_all();
        if (displaced->state != ClosingPeer::State::REMOVING) {
            rail_manager_.removeAllAddresses(displaced->addrs);
        }
    }

    NIXL_DEBUG << (answer ? "Answering the close of agent " : "Closing connection to agent ")
               << rec->name << " (" << countAddrs(rec->addrs) << " AV entries)";

    // Never post from here: this runs wherever the last reference went, which may be the
    // progress thread inside a completion callback.
    queueCmTask([this, rec, answer]() {
        const nixl_status_t status = sendCloseMessage(
            answer ? CtrlType::CLOSE_ACK : CtrlType::CLOSE,
            rec->ctrl_addr,
            false,
            [this, rec, answer](nixl_status_t sent) {
                if (answer) {
                    // An answer that cannot be delivered means the peer is gone.
                    finishClose(rec,
                                true,
                                sent == NIXL_SUCCESS ? "answered the peer's close" :
                                                       "peer unreachable");
                } else if (sent != NIXL_SUCCESS) {
                    finishClose(rec, true, "peer unreachable");
                }
            });
        if (status != NIXL_SUCCESS) {
            // Never left this side, so the peer may still hold its entries for us.
            finishClose(rec, false, "could not send the close message");
        }
    });
    return true;
}

void
nixlLibfabricEngine::finishClose(const std::shared_ptr<ClosingPeer> &rec,
                                 bool remove,
                                 const char *why) {
    {
        const std::lock_guard<std::mutex> lock(close_mutex_);
        auto it = closing_.find(rec->name);
        if (it == closing_.end() || it->second != rec ||
            rec->state == ClosingPeer::State::REMOVING) {
            return; // already ended
        }
        if (!remove && rec->state == ClosingPeer::State::PARKED) {
            return;
        }
        rec->state = remove ? ClosingPeer::State::REMOVING : ClosingPeer::State::PARKED;
    }
    close_cv_.notify_all();

    if (!remove) {
        NIXL_INFO << "Keeping the " << countAddrs(rec->addrs) << " AV entries of agent "
                  << rec->name << ": " << why;
        return;
    }
    // Only the rail-0 pair carries numbered (send/recv) messages, so it is the entry that must
    // be gone before the peer can send to us afresh. Remove it right here: when we answered
    // the peer's CLOSE, the peer re-adds us as soon as its own removal and cooldown are over.
    removeControlEntry(*rec);
    // The rest takes about 15 ms per entry on EFA (each may free an address handle), far too
    // long for the progress thread, which may be the caller here. A re-add meanwhile simply
    // shares them (they are reference counted).
    queueCmTask([this, rec, reason = std::string(why)]() { completeRemoval(rec, reason); });
}

void
nixlLibfabricEngine::removeControlEntry(ClosingPeer &rec) {
    auto rail0 = rec.addrs.find(0);
    if (rail0 == rec.addrs.end()) {
        return;
    }
    for (fi_addr_t &addr : rail0->second) {
        if (addr == rec.ctrl_addr) {
            rail_manager_.getRail(0).removeAddress(addr);
            addr = FI_ADDR_UNSPEC; // removeAllAddresses() skips it
            return;
        }
    }
}

void
nixlLibfabricEngine::completeRemoval(const std::shared_ptr<ClosingPeer> &rec,
                                     const std::string &why) {
    const size_t count = countAddrs(rec->addrs);
    const nixl_status_t status = rail_manager_.removeAllAddresses(rec->addrs);
    {
        const std::lock_guard<std::mutex> lock(close_mutex_);
        auto it = closing_.find(rec->name);
        if (it != closing_.end() && it->second == rec) {
            closing_.erase(it);
        }
        // The cooldown starts once our entries are gone.
        last_close_[rec->name] = Clock::now();
    }
    close_cv_.notify_all();
    if (status != NIXL_SUCCESS) {
        NIXL_WARN << "Releasing the " << count << " AV entries of agent " << rec->name << " ("
                  << why << ") failed partway with status " << status;
        return;
    }
    NIXL_INFO << "Released the " << count << " AV entries of agent " << rec->name << ": "
              << why;
}

void
nixlLibfabricEngine::handleCloseMessage(uint64_t msg_type,
                                        const std::string &payload,
                                        uint32_t sender_idx) {
    const bool is_ack = (msg_type == NIXL_LIBFABRIC_MSG_CLOSE_ACK);
    nixlSerDes sd;
    if (sd.importStr(payload) != NIXL_SUCCESS) {
        NIXL_ERROR << "Failed to deserialize a close message";
        return;
    }
    const std::string name = sd.getStr(NIXL_CLOSE_TAG_NAME);
    uint8_t kept = 0;
    if (name.empty() ||
        (is_ack && sd.getBuf(NIXL_CLOSE_TAG_KEPT, &kept, sizeof(kept)) != NIXL_SUCCESS)) {
        NIXL_ERROR << "Malformed close message (type " << msg_type << ")";
        return;
    }

    // The sender is identified by its source address; its name must agree.
    std::shared_ptr<nixlLibfabricConnection> conn;
    std::shared_ptr<nixlLibfabricConnection> retired;
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        if (sender_idx >= agent_names_.size() || agent_names_[sender_idx] != name) {
            NIXL_WARN << "Dropping close message type " << msg_type << " from '" << name
                      << "': its source address belongs to another agent";
            return;
        }
        auto it = connections_.find(name);
        if (it != connections_.end() && it->second->agent_index_ == sender_idx) {
            conn = it->second;
            if (!is_ack && !conn->core_loaded_.load(std::memory_order_acquire)) {
                // Created only by the peer's handshake, so nothing on this side will use it
                // again. Unregister it; its last reference answers the CLOSE.
                conn->peer_closed_.store(true, std::memory_order_release);
                retired = std::move(it->second);
                connections_.erase(it);
            }
        }
    }

    if (!is_ack && conn) {
        if (retired) {
            NIXL_INFO << "Agent " << name << " closed the connection it opened to us";
            std::vector<std::shared_ptr<nixlLibfabricConnection>> dropped;
            {
                const std::lock_guard<std::mutex> cm_lock(cm_mutex_);
                for (auto it = pending_replies_.begin(); it != pending_replies_.end();) {
                    if (*it == retired) {
                        dropped.push_back(std::move(*it));
                        it = pending_replies_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            return; // dropped, conn and retired let go here, outside every lock
        }
        // Our core still uses the peer: both sides keep their entries until it lets go.
        NIXL_INFO << "Agent " << name << " closed its side; keeping ours, which our core uses";
        queueCmTask([this, conn]() {
            const nixl_status_t status =
                sendCloseMessage(CtrlType::CLOSE_ACK,
                                 conn->rail_remote_addr_list_.at(0).at(0),
                                 true,
                                 [conn](nixl_status_t) {});
            if (status != NIXL_SUCCESS) {
                NIXL_WARN << "Could not answer the close of agent " << conn->remoteAgent_
                          << "; it keeps its entries until its timeout";
            }
        });
        return;
    }

    std::shared_ptr<ClosingPeer> rec;
    bool answer = false;
    {
        const std::lock_guard<std::mutex> lock(close_mutex_);
        auto it = closing_.find(name);
        if (it != closing_.end() && it->second->agent_idx == sender_idx) {
            rec = it->second;
            if (!is_ack &&
                (rec->state == ClosingPeer::State::AWAIT_ACK ||
                 rec->state == ClosingPeer::State::PARKED)) {
                // Our connection is gone too (crossing CLOSEs, or a parked peer): answer
                // "removed", and remove once the answer is out.
                rec->state = ClosingPeer::State::ACKING;
                answer = true;
            }
        }
    }

    if (!rec) {
        if (is_ack && conn) {
            NIXL_WARN << "Late close answer from agent " << name << " (kept=" << int(kept)
                      << ") after it was re-added";
        } else {
            NIXL_DEBUG << "Close message type " << msg_type << " from agent " << name
                       << " for no connection or record; ignoring";
        }
        return;
    }

    if (answer) {
        queueCmTask([this, rec]() {
            const nixl_status_t status = sendCloseMessage(
                CtrlType::CLOSE_ACK, rec->ctrl_addr, false, [this, rec](nixl_status_t sent) {
                    finishClose(rec,
                                true,
                                sent == NIXL_SUCCESS ? "both sides closed" : "peer unreachable");
                });
            if (status != NIXL_SUCCESS) {
                finishClose(rec, false, "could not answer the peer's close");
            }
        });
        return;
    }

    if (!is_ack) {
        return; // a repeated CLOSE while we are already answering
    }

    ClosingPeer::State state;
    bool timed_out;
    {
        const std::lock_guard<std::mutex> lock(close_mutex_);
        state = rec->state;
        timed_out = rec->timed_out;
    }
    if (state == ClosingPeer::State::AWAIT_ACK ||
        (state == ClosingPeer::State::PARKED && timed_out)) {
        finishClose(rec,
                    kept == 0,
                    kept ? "the peer keeps its entries for us" : "both sides closed");
    }
    // ACKING: the peer closed too; our own answer's completion removes the entries.
}

std::optional<std::chrono::steady_clock::time_point>
nixlLibfabricEngine::expireCloses(bool &needs_progress) {
    needs_progress = false;
    std::optional<Clock::time_point> next;
    std::vector<std::shared_ptr<ClosingPeer>> expired;
    const auto now = Clock::now();
    {
        const std::lock_guard<std::mutex> lock(close_mutex_);
        for (auto &[name, rec] : closing_) {
            if (rec->state == ClosingPeer::State::AWAIT_ACK) {
                if (rec->deadline <= now) {
                    rec->timed_out = true;
                    expired.push_back(rec);
                } else {
                    needs_progress = true;
                    if (!next || rec->deadline < *next) {
                        next = rec->deadline;
                    }
                }
            } else if (rec->state == ClosingPeer::State::ACKING) {
                needs_progress = true;
            }
        }
        std::erase_if(last_close_, [&](const auto &entry) {
            return entry.second + reinsert_cooldown_ <= now;
        });
    }
    for (const auto &rec : expired) {
        finishClose(rec,
                    false,
                    "no answer to our close; the peer may run an older NIXL. They are removed "
                    "when the peer closes, or at teardown");
    }
    return next;
}

void
nixlLibfabricEngine::awaitClose(const std::string &agent_name) {
    std::unique_lock<std::mutex> lock(close_mutex_);
    auto busy = [&]() {
        auto it = closing_.find(agent_name);
        return it != closing_.end() && it->second->state != ClosingPeer::State::PARKED;
    };
    if (busy()) {
        NIXL_DEBUG << "Waiting for the close exchange with agent " << agent_name
                   << " before re-adding it";
        if (!close_cv_.wait_for(lock, close_timeout_ + std::chrono::seconds(1), [&]() {
                return !busy();
            })) {
            NIXL_WARN << "Close exchange with agent " << agent_name
                      << " did not finish; re-adding it anyway";
        }
    }
    auto last = last_close_.find(agent_name);
    if (last == last_close_.end()) {
        return;
    }
    const auto ready_at = last->second + reinsert_cooldown_;
    lock.unlock();
    if (Clock::now() < ready_at) {
        std::this_thread::sleep_until(ready_at);
    }
}

void
nixlLibfabricEngine::absorbClose(const std::string &agent_name, bool before_insert) {
    std::shared_ptr<ClosingPeer> rec;
    {
        std::unique_lock<std::mutex> lock(close_mutex_);
        auto it = closing_.find(agent_name);
        if (it == closing_.end()) {
            return;
        }
        if (it->second->state == ClosingPeer::State::REMOVING) {
            // Its control entry is gone already; the insert shares whatever else the CM thread
            // has not removed yet, which carries no numbered messages.
            return;
        }
        const bool parked = (it->second->state == ClosingPeer::State::PARKED);
        if (parked == before_insert) {
            return; // the other call handles it
        }
        rec = std::move(it->second);
        closing_.erase(it);
        if (!parked) {
            last_close_[agent_name] = Clock::now();
        }
    }
    close_cv_.notify_all();

    if (before_insert) {
        // Re-added while the exchange still runs: only a fresh handshake from the peer gets
        // here without awaitClose(), and it means the peer dropped its entries for us. Remove
        // ours before inserting, so both sides start over.
        NIXL_WARN << "Agent " << agent_name
                  << " is re-added while its close exchange still runs; removing its "
                  << countAddrs(rec->addrs) << " old AV entries first";
        // Only the control entry must go before the insert; the rest may be shared, and
        // removing them inline would stall the progress thread (we may be on it).
        removeControlEntry(*rec);
        queueCmTask([this, rec]() { rail_manager_.removeAllAddresses(rec->addrs); });
        return;
    }
    // Both sides kept their entries, so the new connection's references (just taken) keep
    // using them; drop the parked ones.
    NIXL_DEBUG << "Agent " << agent_name << " is re-added; reusing its kept AV entries";
    rail_manager_.removeAllAddresses(rec->addrs);
}

void
nixlLibfabricEngine::closeAllConnections() {
    std::vector<std::shared_ptr<nixlLibfabricConnection>> conns;
    std::deque<std::shared_ptr<nixlLibfabricConnection>> replies;
    {
        std::lock_guard<std::mutex> lock(connection_state_mutex_);
        for (auto it = connections_.begin(); it != connections_.end();) {
            if (it->first == localAgent) {
                ++it;
                continue;
            }
            conns.push_back(std::move(it->second));
            it = connections_.erase(it);
        }
    }
    {
        const std::lock_guard<std::mutex> cm_lock(cm_mutex_);
        replies.swap(pending_replies_);
    }
    NIXL_DEBUG << "Closing " << conns.size() << " connection(s) at teardown";
    // The last references start the exchanges. A connection still held elsewhere (remote
    // metadata the core never unloaded) is left to teardown, which frees our side only.
    replies.clear();
    conns.clear();

    // Also wait for exchanges started earlier (a peer disconnected just before teardown):
    // the peer removes its entries for us only once it gets our CLOSE, or our answer.
    const auto deadline = Clock::now() +
        std::min<std::chrono::milliseconds>(close_timeout_, std::chrono::seconds(1));
    std::unique_lock<std::mutex> lock(close_mutex_);
    const bool done = close_cv_.wait_until(lock, deadline, [this]() {
        for (const auto &[name, rec] : closing_) {
            if (rec->state != ClosingPeer::State::PARKED) {
                return false;
            }
        }
        return true;
    });
    if (!done) {
        NIXL_WARN << "Teardown: some peers did not answer our close in time; they keep their "
                     "entries for us";
    }
}
