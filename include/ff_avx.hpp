#pragma once

#if defined __AVX2__
#include "ff.hpp"
#include <immintrin.h>

//提供了使用AVX2指令集实现的素数域Z_q上的向量化算术操作，包括加法和乘法。
//定义了一个结构体ff_avx_t，用于存储和操作256位寄存器中的四个素数域元素。

// Prime Field ( i.e. Z_q ) Arithmetic | q = 2^64 - 2^32 + 1
namespace ff {

// Given two 256 -bit registers, each holding four 64 -bit unsigned integers,
// this routine computes whether a >= b.
//
// Resulting 256 -bit register holds four 64 -bit limbs, each setting all of its
// bits to 1, if a >= b, otherwise all 64 of those bits ( of that specific limb
// ) is set to 0.
static inline __m256i
gte(const __m256i a, const __m256i b)
{
  // To determine whether a > b | a, b ∈ [0, 2^64), it's enough to compare high
  // 32 -bits of a, b.
  //
  // I've to choose this path due to the fact that `_mm256_cmpgt_epi64`
  // intrinsic treats each 64 -bit limb to be a signed 64 -bit integer, which
  // effectively rounds off operands and that ends up producing wrong comparison
  // result, in a lot of cases.

  const auto t0 = _mm256_srli_epi64(a, 32);
  const auto t1 = _mm256_srli_epi64(b, 32);

  const auto t2 = _mm256_cmpgt_epi64(t0, t1); // is > ?
  const auto t3 = _mm256_cmpeq_epi64(a, b);   // is = ?
  const auto t4 = _mm256_or_si256(t2, t3);    // is >= ?

  return t4;
}

// Given a 256 -bit register, holding four 64 -bit unsigned integers, this
// routine converts each of those four limbs to their canonical representation
// in prime field Z_q i.e. returned register holds four elements ∈ Z_q.
static inline __m256i
reduce(const __m256i a)
{
  const auto q = _mm256_set1_epi64x(ff::Q);

  const auto t0 = gte(a, q);
  const auto t1 = _mm256_and_si256(t0, q);
  const auto t2 = _mm256_sub_epi64(a, t1);

  return t2;
}

// Given two 256 -bit registers, each holding four 64 -bit unsigned integers,
// this routine performs a full multiplication of each 64 -bit wide limb with
// corresponding limb on other register, producing a 128 -bit result, which is
// splitted into high 64 -bits and low 64 -bits, maintained on two different
// resulting registers.
//
// Note, returned 256 -bit register pair holds
//
// - high 64 -bits in first register
// - then low 64 -bits are kept on second register
//
// This routine does exactly what
// https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L15-L50
// does, only difference is that it performs four of those operations at a time.
static inline std::pair<__m256i, __m256i>
full_mul_u64x4(const __m256i lhs, const __m256i rhs)
{
  const auto u32x4 = _mm256_set1_epi64x(UINT32_MAX);

  const auto lhs_hi = _mm256_srli_epi64(lhs, 32);
  const auto rhs_hi = _mm256_srli_epi64(rhs, 32);

  const auto hi = _mm256_mul_epu32(lhs_hi, rhs_hi);
  const auto mid0 = _mm256_mul_epu32(lhs_hi, rhs);
  const auto mid1 = _mm256_mul_epu32(lhs, rhs_hi);
  const auto lo = _mm256_mul_epu32(lhs, rhs);

  const auto mid0_hi = _mm256_srli_epi64(mid0, 32);
  const auto mid0_lo = _mm256_and_si256(mid0, u32x4);
  const auto mid1_hi = _mm256_srli_epi64(mid1, 32);
  const auto mid1_lo = _mm256_and_si256(mid1, u32x4);

  const auto t0 = _mm256_srli_epi64(lo, 32);
  const auto t1 = _mm256_add_epi64(t0, mid0_lo);
  const auto t2 = _mm256_add_epi64(t1, mid1_lo);
  const auto carry = _mm256_srli_epi64(t2, 32);

  const auto t3 = _mm256_add_epi64(hi, mid0_hi);
  const auto t4 = _mm256_add_epi64(t3, mid1_hi);
  const auto res_hi = _mm256_add_epi64(t4, carry);

  const auto t5 = _mm256_slli_epi64(mid0_lo, 32);
  const auto t6 = _mm256_slli_epi64(mid1_lo, 32);
  const auto t7 = _mm256_add_epi64(lo, t5);
  const auto res_lo = _mm256_add_epi64(t7, t6);

  return std::make_pair(res_hi, res_lo);
}

// Four elements of prime field Z_q | q = 2^64 - 2^32 + 1, stored in a 256 -bit
// AVX2 register, loaded *only* from 32 -bytes aligned memory address ( see
// constructor ), defining modular {addition, multiplication} over it.
struct ff_avx_t
{
  __m256i v;

  // Assign a 256 -bit register
  inline constexpr ff_avx_t(const __m256i a) { v = a; }

  // Load four 64 -bit unsigned integers from memory into a 256 -bit register.
  //
  // Ensure that starting memory address is 32 -bytes aligned, otherwise it'll
  // result in a segmentation fault.
  inline ff_avx_t(const ff::ff_t* const arr)
  {
    v = _mm256_load_si256((__m256i*)arr);
  }

  // Given two 256 -bit registers, each holding 4 prime field Z_q elements, this
  // routine performs element wise addition over Z_q and returns result in
  // canonical form i.e. each 64 -bit result limb must ∈ Z_q.
  //
  // This routine does what
  // https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L73-L84
  // does, only difference is that instead of working on single element at a
  // time, it works on four of them.
  inline ff_avx_t operator+(const ff_avx_t& rhs) const
  {
    const auto u64x4 = _mm256_set1_epi64x(UINT64_MAX);

    const auto t0 = _mm256_add_epi64(this->v, rhs.v);
    const auto t1 = _mm256_sub_epi64(u64x4, rhs.v);

    const auto t2 = _mm256_srli_epi64(this->v, 32);
    const auto t3 = _mm256_srli_epi64(t1, 32);
    const auto t4 = _mm256_cmpgt_epi64(t2, t3);

    const auto t5 = _mm256_srli_epi64(t4, 32);
    const auto t6 = _mm256_add_epi64(t0, t5);

    const auto t7 = reduce(t6);
    return ff_avx_t{ t7 };
  }

  // Given two 256 -bit registers, each holding 4 prime field Z_q elements, this
  // routine performs element wise multiplication over Z_q and returns result in
  // canonical form i.e. each 64 -bit result limb must ∈ Z_q.
  //
  // This routine does what
  // https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L102-L125
  // does, only difference is that instead of working on single element at a
  // time, it works on four of them.
  inline ff_avx_t operator*(const ff_avx_t& rhs) const
  {
    const auto u32x4 = _mm256_set1_epi64x(UINT32_MAX);
    const auto u64x4 = _mm256_set1_epi64x(UINT64_MAX);

    const auto res = full_mul_u64x4(this->v, rhs.v);
    const auto res_hi = res.first;
    const auto res_lo = res.second;

    const auto c = _mm256_and_si256(res_hi, u32x4);
    const auto d = _mm256_srli_epi64(res_hi, 32);

    const auto t2 = _mm256_sub_epi64(res_lo, d);
    const auto t3 = _mm256_srli_epi64(res_lo, 32);
    const auto t4 = _mm256_srli_epi64(d, 32);
    const auto t5 = _mm256_cmpgt_epi64(t4, t3);
    const auto t6 = _mm256_srli_epi64(t5, 32);
    const auto t7 = _mm256_sub_epi64(t2, t6);

    const auto t8 = _mm256_slli_epi64(c, 32);
    const auto t9 = _mm256_sub_epi64(t8, c);
    const auto t10 = _mm256_add_epi64(t7, t9);

    const auto t11 = _mm256_sub_epi64(u64x4, t9);
    const auto t12 = _mm256_srli_epi64(t7, 32);
    const auto t13 = _mm256_srli_epi64(t11, 32);
    const auto t14 = _mm256_cmpgt_epi64(t12, t13);
    const auto t15 = _mm256_srli_epi64(t14, 32);
    const auto t16 = _mm256_add_epi64(t10, t15);

    const auto t17 = reduce(t16);
    return ff_avx_t{ t17 };
  }

  // Stores four prime field Z_q elements ( kept in a 256 -bit register ) into
  // 32 -bytes aligned memory s.t. starting memory address is provided. If
  // starting memory address is not aligned to 32 -bytes boundary, it'll result
  // in a segmentation fault.
  inline void store(ff::ff_t* const arr) const
  {
    _mm256_store_si256((__m256i*)arr, this->v);
  }
};

}

#endif
