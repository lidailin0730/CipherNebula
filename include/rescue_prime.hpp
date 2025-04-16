#pragma once
#include "permutation.hpp"

//实现了Rescue Prime哈希函数，提供了一个函数来计算输入元素的哈希值。
// Rescue Prime Hashing over prime field Z_q, q = 2^64 - 2^32 + 1
namespace rescue_prime {

// Given N ( > 0 ) -many Z_q elements as input, this routine computes Rescue
// prime digest of four Z_q elements i.e. 32 -bytes wide.
//
// This implementation is adapted from
// https://github.com/novifinancial/winterfell/blob/21173bd/crypto/src/hash/rescue/rp64_256/mod.rs#L223-L256
static inline void
hash(const ff::ff_t* const __restrict in, // input elements ∈ Z_q
     const size_t ilen,             // number of input elements to be hashed
     ff::ff_t* const __restrict out // 4 output elements ∈ Z_q
)
{
  alignas(32) ff::ff_t state[rescue::STATE_WIDTH]{};
  state[rescue::CAPACITY_BEGINS] = ff::ff_t{ ilen };

  const size_t blk_cnt = ilen >> 3;
  const size_t off = blk_cnt << 3;
  const size_t rm_elms = ilen - off;

  for (size_t i = 0; i < blk_cnt; i++) {
    const size_t ioff = i << 3;

#if defined __GNUC__
#pragma GCC unroll 8
#elif defined __clang__
#pragma unroll 8
#endif
    for (size_t j = 0; j < rescue::RATE; j++) {
      constexpr size_t soff = rescue::RATE_BEGINS;
      state[soff + j] = state[soff + j] + in[ioff + j];
    }

    rescue::permute(state);
  }

  if (rm_elms > 0) {
    for (size_t j = 0; j < rm_elms; j++) {
      constexpr size_t soff = rescue::RATE_BEGINS;
      state[soff + j] = state[soff + j] + in[off + j];
    }

    rescue::permute(state);
  }

  std::memcpy(out, state + rescue::DIGEST_BEGINS, rescue::DIGEST_WIDTH << 3);
}

}
