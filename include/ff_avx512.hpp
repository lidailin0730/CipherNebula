#pragma once

#if defined __AVX512F__
#include "ff.hpp"
#include <immintrin.h>

//提供了使用AVX512指令集实现的素数域Z_q上的向量化算术操作，包括加法和乘法。
//定义了一个结构体ff_avx512_t，用于存储和操作512位寄存器中的八个素数域元素。


// Prime Field ( i.e. Z_q ) Arithmetic | q = 2^64 - 2^32 + 1
namespace ff {

// Given a 512 -bit register, holding eight 64 -bit unsigned integers, this
// routine converts each of those eight limbs to their canonical representation
// in prime field Z_q i.e. returned register holds eight elements ∈ Z_q.
static inline __m512i
reduce(const __m512i a)
{
  const auto q = _mm512_set1_epi64(ff::Q);

  const auto t0 = _mm512_cmpgt_epu64_mask(a, q);
  const auto t1 = _mm512_maskz_set1_epi64(t0, ff::Q);
  const auto t2 = _mm512_sub_epi64(a, t1);

  return t2;
}

// Given two 512 -bit registers, each holding eight 64 -bit unsigned integers,
// this routine performs a full multiplication of each 64 -bit wide limb with
// corresponding limb on other register, producing a 128 -bit result, which is
// splitted into high 64 -bits and low 64 -bits, maintained on two different
// resulting registers.
//
// Note, returned 512 -bit register pair holds
//
// - high 64 -bits in first register
// - then low 64 -bits are kept on second register
//
// This routine does exactly what
// https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L15-L50
// does, only difference is that it performs eight of those operations at a
// time.
static inline std::pair<__m512i, __m512i>
full_mul_u64x8(const __m512i lhs, const __m512i rhs)
{
  const auto u32x8 = _mm512_set1_epi64(UINT32_MAX);

  const auto lhs_hi = _mm512_srli_epi64(lhs, 32);
  const auto rhs_hi = _mm512_srli_epi64(rhs, 32);

  const auto hi = _mm512_mul_epu32(lhs_hi, rhs_hi);
  const auto mid0 = _mm512_mul_epu32(lhs_hi, rhs);
  const auto mid1 = _mm512_mul_epu32(lhs, rhs_hi);
  const auto lo = _mm512_mul_epu32(lhs, rhs);

  const auto mid0_hi = _mm512_srli_epi64(mid0, 32);
  const auto mid0_lo = _mm512_and_si512(mid0, u32x8);
  const auto mid1_hi = _mm512_srli_epi64(mid1, 32);
  const auto mid1_lo = _mm512_and_si512(mid1, u32x8);

  const auto t0 = _mm512_srli_epi64(lo, 32);
  const auto t1 = _mm512_add_epi64(t0, mid0_lo);
  const auto t2 = _mm512_add_epi64(t1, mid1_lo);
  const auto carry = _mm512_srli_epi64(t2, 32);

  const auto t3 = _mm512_add_epi64(hi, mid0_hi);
  const auto t4 = _mm512_add_epi64(t3, mid1_hi);
  const auto res_hi = _mm512_add_epi64(t4, carry);

  const auto t5 = _mm512_slli_epi64(mid0_lo, 32);
  const auto t6 = _mm512_slli_epi64(mid1_lo, 32);
  const auto t7 = _mm512_add_epi64(lo, t5);
  const auto res_lo = _mm512_add_epi64(t7, t6);

  return std::make_pair(res_hi, res_lo);
}

// Eight elements of the prime field Z_q | q = 2^64 - 2^32 + 1, stored in a 512
// -bit AVX512 register, loaded *only* from 64 -bytes aligned memory address (
// see constructor ), defining modular {addition, multiplication} over it, used
// for implementing Rescue permutation.
struct ff_avx512_t
{
  __m512i v;

  // Assign a 512 -bit register
  inline constexpr ff_avx512_t(const __m512i a) { v = a; }

  // Load eight 64 -bit unsigned integers from memory into a 512 -bit register.
  //
  // Ensure that starting memory address is 64 -bytes aligned, otherwise it'll
  // result in a segmentation fault.
  inline ff_avx512_t(const ff::ff_t* const arr) { v = _mm512_load_epi64(arr); }

  // Given two 512 -bit registers, each holding eight prime field Z_q elements,
  // this routine performs element wise addition over Z_q and returns result in
  // canonical form i.e. each 64 -bit result limb must ∈ Z_q.
  //
  // This routine does what
  // https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L73-L84
  // does, only difference is that instead of working on single element at a
  // time, it works on eight of them.
  inline ff_avx512_t operator+(const ff_avx512_t& rhs) const
  {
    const auto u64x8 = _mm512_set1_epi64(UINT64_MAX);

    const auto t0 = _mm512_add_epi64(this->v, rhs.v);
    const auto t1 = _mm512_sub_epi64(u64x8, rhs.v);
    const auto t2 = _mm512_cmpgt_epu64_mask(this->v, t1);
    const auto t3 = _mm512_maskz_set1_epi64(t2, UINT32_MAX);
    const auto t4 = _mm512_add_epi64(t0, t3);

    const auto t5 = reduce(t4);
    return ff_avx512_t{ t5 };
  }

  // Given two 512 -bit registers, each holding 8 prime field Z_q elements, this
  // routine performs element wise multiplication over Z_q and returns result in
  // canonical form i.e. each 64 -bit result limb must ∈ Z_q.
  //
  // This routine does what
  // https://github.com/itzmeanjan/rescue-prime/blob/22b7aa5/include/ff.hpp#L102-L125
  // does, only difference is that instead of working on single element at a
  // time, it works on eight of them.
  inline ff_avx512_t operator*(const ff_avx512_t& rhs) const
  {
    const auto u32x8 = _mm512_set1_epi64(UINT32_MAX);
    const auto u64x8 = _mm512_set1_epi64(UINT64_MAX);

    const auto [res_hi, res_lo] = full_mul_u64x8(this->v, rhs.v);

    const auto c = _mm512_and_si512(res_hi, u32x8);
    const auto d = _mm512_srli_epi64(res_hi, 32);

    const auto t2 = _mm512_sub_epi64(res_lo, d);
    const auto t3 = _mm512_cmpgt_epu64_mask(d, res_lo);
    const auto t4 = _mm512_maskz_set1_epi64(t3, UINT32_MAX);
    const auto t5 = _mm512_sub_epi64(t2, t4);

    const auto t6 = _mm512_slli_epi64(c, 32);
    const auto t7 = _mm512_sub_epi64(t6, c);
    const auto t8 = _mm512_add_epi64(t5, t7);

    const auto t9 = _mm512_sub_epi64(u64x8, t7);
    const auto t10 = _mm512_cmpgt_epu64_mask(t5, t9);
    const auto t11 = _mm512_maskz_set1_epi64(t10, UINT32_MAX);
    const auto t12 = _mm512_add_epi64(t8, t11);

    const auto t13 = reduce(t12);
    return ff_avx512_t{ t13 };
  }

  // Stores eight prime field Z_q elements ( kept in a 512 -bit register ) into
  // 64 -bytes aligned memory s.t. starting memory address is provided.
  //
  // If starting memory address is not aligned to 64 -bytes boundary, it'll
  // result in a segmentation fault.
  inline void store(ff::ff_t* const arr) const
  {
    _mm512_store_epi64(arr, this->v);
  }
};

}

#endif
