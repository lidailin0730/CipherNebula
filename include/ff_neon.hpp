#pragma once

#if defined __ARM_NEON
#include "ff.hpp"
#include <arm_neon.h>

// Prime Field ( i.e. Z_q ) Arithmetic | q = 2^64 - 2^32 + 1
namespace ff {

// Given a 128 -bit register, holding two 64 -bit unsigned integers, this
// routine converts each of those two limbs into their canonical representation
// in prime field Z_q, by reducing using prime modulus Q = 2^64 - 2^32 + 1
//
// This routine does exactly what
// https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L62-L64
// does, but it reduces two field elements at a time.
static inline uint64x2_t
reduce(const uint64x2_t a)
{
  const auto q = vdupq_n_u64(ff::Q);

  const auto t0 = vcgeq_u64(a, q);
  const auto t1 = vandq_u64(t0, q);
  const auto t2 = vsubq_u64(a, t1);

  return t2;
}

// Given two 128 -bit registers, each holding two 64 -bit unsigned integers,
// this routine performs a full multiplication of each 64 -bit wide limb with
// corresponding limb on other register, producing a 128 -bit result, which is
// splitted into high 64 -bits and low 64 -bits, maintained on two different
// resulting 128 -bit registers.
//
// Note, returned 128 -bit register pair holds
//
// - high 64 -bits in first register
// - then low 64 -bits are kept on the second register
//
// This routine does exactly what
// https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L15-L50
// does, only difference is that it performs two of those operations at a time.
static inline std::pair<uint64x2_t, uint64x2_t>
full_mul_u64x2(const uint64x2_t lhs, const uint64x2_t rhs)
{
  const auto u32x2 = vdupq_n_u64(0xfffffffful);

  const auto lhs_hi_ = vreinterpretq_u32_u64(vshrq_n_u64(lhs, 32));
  const auto lhs_lo_ = vreinterpretq_u32_u64(vandq_u64(lhs, u32x2));
  const auto rhs_hi_ = vreinterpretq_u32_u64(vshrq_n_u64(rhs, 32));
  const auto rhs_lo_ = vreinterpretq_u32_u64(vandq_u64(rhs, u32x2));

  const auto lhs_hi = vtrn1_u32(vget_low_u32(lhs_hi_), vget_high_u32(lhs_hi_));
  const auto lhs_lo = vtrn1_u32(vget_low_u32(lhs_lo_), vget_high_u32(lhs_lo_));
  const auto rhs_hi = vtrn1_u32(vget_low_u32(rhs_hi_), vget_high_u32(rhs_hi_));
  const auto rhs_lo = vtrn1_u32(vget_low_u32(rhs_lo_), vget_high_u32(rhs_lo_));

  const auto hi = vmull_u32(lhs_hi, rhs_hi);
  const auto mid0 = vmull_u32(lhs_hi, rhs_lo);
  const auto mid1 = vmull_u32(lhs_lo, rhs_hi);
  const auto lo = vmull_u32(lhs_lo, rhs_lo);

  const auto mid0_hi = vshrq_n_u64(mid0, 32);
  const auto mid0_lo = vandq_u64(mid0, u32x2);
  const auto mid1_hi = vshrq_n_u64(mid1, 32);
  const auto mid1_lo = vandq_u64(mid1, u32x2);

  const auto t0 = vshrq_n_u64(lo, 32);
  const auto t1 = vaddq_u64(t0, mid0_lo);
  const auto t2 = vaddq_u64(t1, mid1_lo);
  const auto carry = vshrq_n_u64(t2, 32);

  const auto t3 = vaddq_u64(hi, mid0_hi);
  const auto t4 = vaddq_u64(t3, mid1_hi);
  const auto res_hi = vaddq_u64(t4, carry);

  const auto t5 = vshlq_n_u64(mid0_lo, 32);
  const auto t6 = vshlq_n_u64(mid1_lo, 32);
  const auto t7 = vaddq_u64(lo, t5);
  const auto res_lo = vaddq_u64(t7, t6);

  return std::make_pair(res_hi, res_lo);
}

// Two elements of prime field Z_q | q = 2^64 - 2^32 + 1, stored in a 128 -bit
// Neon register, defining modular {addition, multiplication} over it.
struct ff_neon_t
{
  uint64x2_t v;

  // Assign a 128 -bit register
  inline constexpr ff_neon_t(const uint64x2_t a) { v = a; }

  // Load two consecutive 64 -bit unsigned integers from memory into a 128 -bit
  // register.
  inline ff_neon_t(const ff::ff_t* const arr)
  {
    v = vld1q_u64(reinterpret_cast<const uint64_t*>(arr));
  }

  // Given two 128 -bit registers, each holding two prime field Z_q elements,
  // this routine performs element wise addition over Z_q and returns result in
  // canonical form i.e. each 64 -bit result limb must ∈ Z_q.
  //
  // This routine does what
  // https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L73-L84
  // does, only difference is that instead of working on single element at a
  // time, it works on two of them.
  inline ff_neon_t operator+(const ff_neon_t& rhs) const
  {
    const auto u64x2 = vdupq_n_u64(UINT64_MAX);

    const auto t0 = vaddq_u64(this->v, rhs.v);

    const auto t1 = vsubq_u64(u64x2, rhs.v);
    const auto t2 = vcgtq_u64(this->v, t1);
    const auto t3 = vshrq_n_u64(t2, 32);
    const auto t4 = vaddq_u64(t0, t3);

    const auto t5 = reduce(t4);
    return ff_neon_t{ t5 };
  }

  // Given two 128 -bit registers, each holding two prime field Z_q elements,
  // this routine performs element wise multiplication over Z_q and returns
  // result in canonical form i.e. each 64 -bit result limb must ∈ Z_q.
  //
  // This routine does what
  // https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L102-L125
  // does, only difference is that instead of working on single element at a
  // time, it works on two of them.
  inline ff_neon_t operator*(const ff_neon_t& rhs) const
  {
    const auto u32x2 = vdupq_n_u64(static_cast<uint64_t>(UINT32_MAX));
    const auto u64x2 = vdupq_n_u64(UINT64_MAX);

    const auto res = full_mul_u64x2(this->v, rhs.v);
    const auto res_hi = res.first;
    const auto res_lo = res.second;

    const auto c = vandq_u64(res_hi, u32x2);
    const auto d = vshrq_n_u64(res_hi, 32);

    const auto t2 = vsubq_u64(res_lo, d);
    const auto t3 = vcltq_u64(res_lo, d);
    const auto t4 = vshrq_n_u64(t3, 32);
    const auto t5 = vsubq_u64(t2, t4);

    const auto t6 = vshlq_n_u64(c, 32);
    const auto t7 = vsubq_u64(t6, c);
    const auto t8 = vaddq_u64(t5, t7);

    const auto t9 = vsubq_u64(u64x2, t7);
    const auto t10 = vcgtq_u64(t5, t9);
    const auto t11 = vshrq_n_u64(t10, 32);
    const auto t12 = vaddq_u64(t8, t11);

    const auto t13 = reduce(t12);
    return ff_neon_t{ t13 };
  }

  // Stores two prime field Z_q elements ( kept in a 128 -bit register )
  inline void store(ff::ff_t* const arr) const
  {
    vst1q_u64(reinterpret_cast<uint64_t*>(arr), this->v);
  }
};

}

#endif
