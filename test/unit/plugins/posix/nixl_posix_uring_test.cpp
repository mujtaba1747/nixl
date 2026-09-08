/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <iostream>
#include <liburing.h>
#include <stdexcept>
#include <thread>
#include <unistd.h>

#include "io_queue.h"
#include "posix_backend.h"

#ifndef LIBURING_NOEXCEPT
#define LIBURING_NOEXCEPT
#endif

namespace {
constexpr int request_count = 32, ring_entries = 16, max_poll_iterations = 2000;
constexpr size_t block_size = 4096;
constexpr auto poll_pause = std::chrono::microseconds(50);
using buffers_t = std::array<std::array<char, block_size>, request_count>;

enum class submit_mode_t { PARTIAL_ONLY, TRANSIENT_ERRORS, SHORT_READ, PASS_THROUGH };
submit_mode_t submit_mode = submit_mode_t::PASS_THROUGH;
int submit_calls = 0, transient_submit_errors = 0, cancel_completions = 0;
unsigned first_ready = 0, first_submitted = 0;
int read_submissions = 0;
int short_read_submissions = 0;
std::array<unsigned, 3> short_read_lengths{};
std::array<off_t, 3> short_read_offsets{};
std::array<uintptr_t, 3> short_read_buffers{};

struct completionState {
    int count = 0, errors = 0;
};

void
completionCallback(void *ctx, uint32_t, int error) {
    auto *state = static_cast<completionState *>(ctx);
    state->count++;
    state->errors += error != 0;
}

void
cancelCompletionCallback(void *) {
    cancel_completions++;
}

struct uringTest {
    int fd = -1;
    buffers_t buffers{};
    std::unique_ptr<nixlPosixIOQueue> queue;

    explicit uringTest(submit_mode_t mode)
        : queue(nixlPosixIOQueue::instantiate("URING", 64, ring_entries)) {
        submit_mode = mode;
        submit_calls = transient_submit_errors = cancel_completions = first_ready =
            first_submitted = 0;
        read_submissions = 0;
        short_read_submissions = 0;
        short_read_lengths.fill(0);
        short_read_offsets.fill(0);
        short_read_buffers.fill(0);
        char path[] = "/tmp/nixl_uring_test_XXXXXX";
        if ((fd = mkstemp(path)) < 0) {
            throw std::runtime_error("mkstemp failed");
        }
        unlink(path);
        for (size_t i = 0; i < buffers.size(); i++) {
            std::memset(buffers[i].data(), static_cast<int>(i + 1), buffers[i].size());
        }
    }

    ~uringTest() {
        queue.reset();
        close(fd);
    }

    bool
    enqueue(completionState &state, int start, int count) {
        for (int i = start; i < start + count; i++) {
            if (queue->enqueue(fd,
                               buffers[i].data(),
                               block_size,
                               i * block_size,
                               false,
                               completionCallback,
                               &state) != NIXL_SUCCESS) {
                return false;
            }
        }
        return true;
    }

    nixl_status_t
    drain() {
        nixl_status_t status = NIXL_IN_PROG;
        for (int i = 0; i < max_poll_iterations && status == NIXL_IN_PROG; i++) {
            status = queue->poll();
            std::this_thread::sleep_for(poll_pause);
        }
        return status;
    }
};

struct uringRequest {
    nixl_meta_dlist_t local{DRAM_SEG};
    nixl_meta_dlist_t remote{FILE_SEG};
    nixl_xfer_op_t operation = NIXL_WRITE;
    nixlPosixBackendReqH request;

    uringRequest(uringTest &test,
                 nixlPosixFileMD &file_md,
                 int index,
                 nixl_xfer_op_t op = NIXL_WRITE)
        : local([&] {
              nixl_meta_dlist_t list(DRAM_SEG);
              list.addDesc(nixlMetaDesc(
                  reinterpret_cast<uintptr_t>(test.buffers[index].data()), block_size, 0, nullptr));
              return list;
          }()),
          remote([&] {
              nixl_meta_dlist_t list(FILE_SEG);
              list.addDesc(nixlMetaDesc(index * block_size, block_size, test.fd, &file_md));
              return list;
          }()),
          operation(op),
          request(operation, local, remote, test.queue) {}
};

#define URING_CHECK(condition)                                                        \
    do {                                                                              \
        if (!(condition)) {                                                           \
            std::cerr << "URING_CHECK failed at line " << __LINE__ << ": " #condition \
                      << std::endl;                                                   \
            return 1;                                                                 \
        }                                                                             \
    } while (false)
} // namespace

extern "C" int
io_uring_submit(struct io_uring *ring) LIBURING_NOEXCEPT {
    using submit_fn = int (*)(struct io_uring *);
    static auto real_submit = reinterpret_cast<submit_fn>(dlsym(RTLD_NEXT, "io_uring_submit"));
    if (!real_submit) {
        return -EINVAL;
    }
    if (submit_mode == submit_mode_t::TRANSIENT_ERRORS && transient_submit_errors == 0) {
        transient_submit_errors++;
        return -EAGAIN;
    }

    const unsigned ready = io_uring_sq_ready(ring);
    for (unsigned i = 0; i < ready; i++) {
        unsigned index = (ring->sq.sqe_head + i) & *ring->sq.kring_mask;
        if (ring->sq.sqes[index].opcode == IORING_OP_READ) {
            read_submissions++;
        }
    }
    if (submit_mode == submit_mode_t::SHORT_READ) {
        for (unsigned i = 0; i < ready; i++) {
            unsigned index = (ring->sq.sqe_head + i) & *ring->sq.kring_mask;
            struct io_uring_sqe *sqe = &ring->sq.sqes[index];
            if (sqe->opcode != IORING_OP_READ) {
                continue;
            }
            if (short_read_submissions < static_cast<int>(short_read_lengths.size())) {
                short_read_lengths[short_read_submissions] = sqe->len;
                short_read_offsets[short_read_submissions] = sqe->off;
                short_read_buffers[short_read_submissions] = sqe->addr;
            }
            if (short_read_submissions < 2) {
                sqe->len /= 2;
            }
            short_read_submissions++;
        }
        return real_submit(ring);
    }
    if (ready == 0 || submit_mode == submit_mode_t::PASS_THROUGH || ++submit_calls != 1 ||
        ready < 2) {
        return real_submit(ring);
    }

    const unsigned original_tail = ring->sq.sqe_tail;
    ring->sq.sqe_tail = ring->sq.sqe_head + ready / 2;
    const int ret = real_submit(ring);
    ring->sq.sqe_tail = original_tail;
    first_ready = ready;
    first_submitted = ret > 0 ? static_cast<unsigned>(ret) : 0;
    return ret;
}

int
main() {
    io_uring probe_ring{};
    io_uring_params probe_params{};
    int probe_ret = io_uring_queue_init_params(ring_entries, &probe_ring, &probe_params);
    if (probe_ret < 0) {
        std::cerr << "io_uring backend test requires a usable ring: " << std::strerror(-probe_ret)
                  << " (" << probe_ret << ")" << std::endl;
        return 1;
    }
    io_uring_queue_exit(&probe_ring);

    {
        uringTest test(submit_mode_t::PARTIAL_ONLY);
        completionState state;
        URING_CHECK(test.enqueue(state, 0, request_count));
        URING_CHECK(test.queue->post() == NIXL_IN_PROG);
        URING_CHECK(first_submitted > 0 && first_submitted < first_ready);
        URING_CHECK(test.drain() == NIXL_SUCCESS);
        URING_CHECK(state.count == request_count && !state.errors && submit_calls > 1);
    }
    {
        uringTest test(submit_mode_t::TRANSIENT_ERRORS);
        completionState state;
        URING_CHECK(test.enqueue(state, 0, request_count));
        URING_CHECK(test.queue->post() == NIXL_IN_PROG);
        URING_CHECK(test.drain() == NIXL_SUCCESS && transient_submit_errors == 1);
        URING_CHECK(state.count == request_count && !state.errors);
    }
    {
        uringTest test(submit_mode_t::SHORT_READ);
        std::array<char, block_size> expected;
        std::memset(expected.data(), 0x5a, expected.size());
        URING_CHECK(pwrite(test.fd, expected.data(), expected.size(), 0) ==
                    static_cast<ssize_t>(expected.size()));
        std::memset(test.buffers[0].data(), 0, block_size);

        nixlPosixFileMD file_md(test.fd, "");
        uringRequest read(test, file_md, 0, NIXL_READ);
        nixl_status_t status = read.request.postXfer();
        URING_CHECK(status == NIXL_IN_PROG);
        URING_CHECK(short_read_submissions == 1);

        for (int expected_submissions = 2; expected_submissions <= 3; expected_submissions++) {
            for (int i = 0; i < max_poll_iterations &&
                 short_read_submissions < expected_submissions && status == NIXL_IN_PROG;
                 i++) {
                status = read.request.checkXfer();
                std::this_thread::sleep_for(poll_pause);
            }
            URING_CHECK(short_read_submissions == expected_submissions);
            URING_CHECK(status == NIXL_IN_PROG);
        }

        for (int i = 0; i < max_poll_iterations && status == NIXL_IN_PROG; i++) {
            status = read.request.checkXfer();
            std::this_thread::sleep_for(poll_pause);
        }
        URING_CHECK(status == NIXL_SUCCESS);
        URING_CHECK(short_read_lengths[0] == block_size);
        URING_CHECK(short_read_lengths[1] == block_size / 2);
        URING_CHECK(short_read_lengths[2] == block_size / 4);
        URING_CHECK(short_read_offsets[0] == 0);
        URING_CHECK(short_read_offsets[1] == static_cast<off_t>(block_size / 2));
        URING_CHECK(short_read_offsets[2] == static_cast<off_t>(3 * block_size / 4));
        uintptr_t first_buffer = reinterpret_cast<uintptr_t>(test.buffers[0].data());
        URING_CHECK(short_read_buffers[0] == first_buffer);
        URING_CHECK(short_read_buffers[1] == first_buffer + block_size / 2);
        URING_CHECK(short_read_buffers[2] == first_buffer + 3 * block_size / 4);
        URING_CHECK(std::memcmp(test.buffers[0].data(), expected.data(), block_size) == 0);
    }
    {
        uringTest test(submit_mode_t::PASS_THROUGH);
        nixlPosixFileMD file_md(test.fd, "");
        uringRequest read_past_eof(test, file_md, 0, NIXL_READ);

        URING_CHECK(read_past_eof.request.postXfer() == NIXL_IN_PROG);
        nixl_status_t status = NIXL_IN_PROG;
        for (int i = 0; i < max_poll_iterations && status == NIXL_IN_PROG; i++) {
            status = read_past_eof.request.checkXfer();
            std::this_thread::sleep_for(poll_pause);
        }
        URING_CHECK(status == NIXL_ERR_BACKEND);
        URING_CHECK(read_submissions == 1);
    }
    {
        uringTest test(submit_mode_t::PASS_THROUGH);
        std::array<char, block_size> expected;
        std::memset(expected.data(), 0x6b, expected.size());
        URING_CHECK(pwrite(test.fd, expected.data(), expected.size(), 0) ==
                    static_cast<ssize_t>(expected.size()));
        URING_CHECK(ftruncate(test.fd, block_size / 2) == 0);
        std::memset(test.buffers[0].data(), 0, block_size);

        nixlPosixFileMD file_md(test.fd, "");
        uringRequest read_truncated(test, file_md, 0, NIXL_READ);
        nixl_status_t status = read_truncated.request.postXfer();
        URING_CHECK(status == NIXL_IN_PROG);
        for (int i = 0; i < max_poll_iterations && status == NIXL_IN_PROG; i++) {
            status = read_truncated.request.checkXfer();
            std::this_thread::sleep_for(poll_pause);
        }
        URING_CHECK(status == NIXL_ERR_BACKEND);
        URING_CHECK(read_submissions == 2);
        URING_CHECK(std::memcmp(test.buffers[0].data(), expected.data(), block_size / 2) == 0);
    }
    {
        uringTest test(submit_mode_t::PASS_THROUGH);
        nixlPosixFileMD file_md(test.fd, "");
        uringRequest cancelled(test, file_md, 0), unrelated(test, file_md, 1);
        nixl_status_t cancelled_status = cancelled.request.postXfer();
        URING_CHECK(cancelled_status >= NIXL_IN_PROG);
        URING_CHECK(test.queue->cancel(&cancelled.request, cancelCompletionCallback) == 1);

        nixl_status_t status = unrelated.request.postXfer();
        URING_CHECK(status >= NIXL_IN_PROG);
        for (int i = 0; i < max_poll_iterations && status == NIXL_IN_PROG; i++) {
            status = unrelated.request.checkXfer();
            std::this_thread::sleep_for(poll_pause);
        }
        URING_CHECK(status == NIXL_SUCCESS);

        for (int i = 0; i < max_poll_iterations && cancelled_status == NIXL_IN_PROG; i++) {
            cancelled_status = cancelled.request.checkXfer();
            std::this_thread::sleep_for(poll_pause);
        }
        URING_CHECK(cancelled_status == NIXL_SUCCESS || cancelled_status == NIXL_ERR_BACKEND);
        URING_CHECK(test.drain() == NIXL_SUCCESS && cancel_completions == 1);
    }
    return 0;
}
