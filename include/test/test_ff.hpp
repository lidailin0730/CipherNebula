#pragma once
#include "ff.hpp"
#include "ff_avx.hpp"
#include "ff_avx512.hpp"
#include "ff_neon.hpp"
#include <cassert>

// Test functional correctness of Rescue Prime implementation
namespace test_rphash {

// Test functional correctness of prime field ( i.e. Z_q ) operations, by
// running through multiple rounds ( see template parameter ) of execution of
// field operations on randomly sampled field element
template<const size_t rounds = 1024ul>
void
test_field_ops()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<size_t> dis{ 0ul, 1ul << 20 };

  for (size_t i = 0; i < rounds; i++) {
    const auto a = ff::ff_t::random();
    const auto b = ff::ff_t::random();

    // addition, subtraction, negation
    const auto c = a - b;
    const auto d = -b;
    const auto e = a + d;

    assert(c == e);

    // multiplication, division, inversion
    const auto f = a * b;
    const auto g = f / b;

    if (b == ff::ff_t::zero()) {
      assert(g == ff::ff_t::zero());
    } else {
      assert(g == a);
    }

    const auto h = a.inv();
    const auto k = h * a;

    if (a == ff::ff_t::zero()) {
      assert(k == ff::ff_t::zero());
    } else {
      assert(k == ff::ff_t::one());
    }

    // exponentiation, multiplication
    const size_t exp = dis(gen);
    const auto l = a ^ exp;

    auto res = ff::ff_t::one();
    for (size_t j = 0; j < exp; j++) {
      res = res * a;
    }

    assert(res == l);
  }
}

#if defined __AVX2__

// Test that vectorized modulo addition over Z_q is implemented correctly
// by checking computed values against scalar implementation.
template<const size_t rounds = 256ul>
void
test_avx_mod_add()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  alignas(32) ff::ff_t arr0[4 * rounds];
  alignas(32) ff::ff_t arr1[4 * rounds];
  alignas(32) ff::ff_t computed_res[4 * rounds];
  alignas(32) ff::ff_t expected_res[4 * rounds];

  // generate some random Z_q elements
  for (size_t i = 0; i < 4 * rounds; i++) {
    arr0[i] = ff::ff_t::random();
    arr1[i] = ff::ff_t::random();
  }

  // compute modulo addition over Z_q, using scalar implementation
  for (size_t i = 0; i < 4 * rounds; i++) {
    expected_res[i] = arr0[i] + arr1[i];
  }

  // compute modulo addition over Z_q, using AVX2 implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 4;

    const ff::ff_avx_t a{ arr0 + off };
    const ff::ff_avx_t b{ arr1 + off };

    const ff::ff_avx_t c = a + b;
    c.store(computed_res + off);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 4 * rounds; i++) {
    assert(computed_res[i] == expected_res[i]);
  }
}

// Ensure that vectorized u64 x u64 -> u128, multiplication using AVX2
// intrinsics, is correctly implemented, by checking computed results against
// scalar implementation.
template<const size_t rounds = 256ul>
void
test_avx_full_mul()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis{};

  alignas(32) uint64_t arr0[4 * rounds];
  alignas(32) uint64_t arr1[4 * rounds];
  alignas(32) uint64_t computed_res_hi[4 * rounds];
  alignas(32) uint64_t computed_res_lo[4 * rounds];
  alignas(32) uint64_t expected_res_hi[4 * rounds];
  alignas(32) uint64_t expected_res_lo[4 * rounds];

  // generate some random u64s
  for (size_t i = 0; i < 4 * rounds; i++) {
    arr0[i] = dis(gen);
    arr1[i] = dis(gen);
  }

  // compute full multiplication of two u64s, resulting into high and low
  // 64 -bit halves
  for (size_t i = 0; i < 4 * rounds; i++) {
    const auto res = ff::full_mul_u64(arr0[i], arr1[i]);

    expected_res_hi[i] = res.first;
    expected_res_lo[i] = res.second;
  }

  // compute full mutliplication of two u64s, resulting into high and low
  // 64 -bit halves, using AVX2 implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 4;

    const auto a = _mm256_load_si256((__m256i*)(arr0 + off));
    const auto b = _mm256_load_si256((__m256i*)(arr1 + off));

    const auto res = ff::full_mul_u64x4(a, b);

    _mm256_store_si256((__m256i*)(computed_res_hi + off), res.first);
    _mm256_store_si256((__m256i*)(computed_res_lo + off), res.second);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 4 * rounds; i++) {
    assert(computed_res_hi[i] == expected_res_hi[i]);
    assert(computed_res_lo[i] == expected_res_lo[i]);
  }
}

// Test that vectorized ( using AVX2 ) modulo multiplication over Z_q is
// implemented correctly by checking computed values against scalar
// implementation.
template<const size_t rounds = 256ul>
void
test_avx_mod_mul()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  alignas(32) ff::ff_t arr0[4 * rounds];
  alignas(32) ff::ff_t arr1[4 * rounds];
  alignas(32) ff::ff_t computed_res[4 * rounds];
  alignas(32) ff::ff_t expected_res[4 * rounds];

  // generate some random Z_q elements
  for (size_t i = 0; i < 4 * rounds; i++) {
    arr0[i] = ff::ff_t::random();
    arr1[i] = ff::ff_t::random();
  }

  // compute modulo multiplication over Z_q, using scalar implementation
  for (size_t i = 0; i < 4 * rounds; i++) {
    expected_res[i] = arr0[i] * arr1[i];
  }

  // compute modulo multiplication over Z_q, using AVX2 implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 4;

    const ff::ff_avx_t a{ arr0 + off };
    const ff::ff_avx_t b{ arr1 + off };

    const ff::ff_avx_t c = a * b;
    c.store(computed_res + off);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 4 * rounds; i++) {
    assert(computed_res[i] == expected_res[i]);
  }
}

#endif

#if defined __ARM_NEON

// Test that vectorized ( using NEON intrinsics ) modulo addition over Z_q is
// implemented correctly by checking computed values against scalar
// implementation.
template<const size_t rounds = 256ul>
void
test_neon_mod_add()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  alignas(32) ff::ff_t arr0[2 * rounds];
  alignas(32) ff::ff_t arr1[2 * rounds];
  alignas(32) ff::ff_t computed_res[2 * rounds];
  alignas(32) ff::ff_t expected_res[2 * rounds];

  // generate some random Z_q elements
  for (size_t i = 0; i < 2 * rounds; i++) {
    arr0[i] = ff::ff_t::random();
    arr1[i] = ff::ff_t::random();
  }

  // compute modulo addition over Z_q, using scalar implementation
  for (size_t i = 0; i < 2 * rounds; i++) {
    expected_res[i] = arr0[i] + arr1[i];
  }

  // compute modulo addition over Z_q, using NEON implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 2;

    const ff::ff_neon_t a{ arr0 + off };
    const ff::ff_neon_t b{ arr1 + off };

    const auto c = a + b;
    c.store(computed_res + off);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 2 * rounds; i++) {
    assert(computed_res[i] == expected_res[i]);
  }
}

// Ensure that vectorized u64 x u64 -> u128, multiplication using NEON
// intrinsics, is correctly implemented, by checking computed results against
// scalar implementation.
template<const size_t rounds = 256ul>
void
test_neon_full_mul()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis{};

  alignas(32) uint64_t arr0[2 * rounds];
  alignas(32) uint64_t arr1[2 * rounds];
  alignas(32) uint64_t computed_res_hi[2 * rounds];
  alignas(32) uint64_t computed_res_lo[2 * rounds];
  alignas(32) uint64_t expected_res_hi[2 * rounds];
  alignas(32) uint64_t expected_res_lo[2 * rounds];

  // generate some random u64s
  for (size_t i = 0; i < 2 * rounds; i++) {
    arr0[i] = dis(gen);
    arr1[i] = dis(gen);
  }

  // compute full multiplication of two u64s, resulting into high and low
  // 64 -bit halves
  for (size_t i = 0; i < 2 * rounds; i++) {
    const auto res = ff::full_mul_u64(arr0[i], arr1[i]);

    expected_res_hi[i] = res.first;
    expected_res_lo[i] = res.second;
  }

  // compute full mutliplication of two u64s, resulting into high and low
  // 64 -bit halves, using NEON implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 2;

    const auto a = vld1q_u64(arr0 + off);
    const auto b = vld1q_u64(arr1 + off);

    const auto res = ff::full_mul_u64x2(a, b);

    vst1q_u64(computed_res_hi + off, res.first);
    vst1q_u64(computed_res_lo + off, res.second);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 2 * rounds; i++) {
    assert(computed_res_hi[i] == expected_res_hi[i]);
    assert(computed_res_lo[i] == expected_res_lo[i]);
  }
}

// Test that vectorized ( using NEON intrinsics ) modulo multiplication over Z_q
// is implemented correctly by checking computed values against scalar
// implementation.
template<const size_t rounds = 256ul>
void
test_neon_mod_mul()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  alignas(32) ff::ff_t arr0[2 * rounds];
  alignas(32) ff::ff_t arr1[2 * rounds];
  alignas(32) ff::ff_t computed_res[2 * rounds];
  alignas(32) ff::ff_t expected_res[2 * rounds];

  // generate some random Z_q elements
  for (size_t i = 0; i < 2 * rounds; i++) {
    arr0[i] = ff::ff_t::random();
    arr1[i] = ff::ff_t::random();
  }

  // compute modulo multiplication over Z_q, using scalar implementation
  for (size_t i = 0; i < 2 * rounds; i++) {
    expected_res[i] = arr0[i] * arr1[i];
  }

  // compute modulo multiplication over Z_q, using NEON implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 2;

    const ff::ff_neon_t a{ arr0 + off };
    const ff::ff_neon_t b{ arr1 + off };

    const ff::ff_neon_t c = a * b;
    c.store(computed_res + off);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 2 * rounds; i++) {
    assert(computed_res[i] == expected_res[i]);
  }
}

#endif

#if defined __AVX512F__

// Test that vectorized ( using AVX512 ) modulo addition over Z_q is implemented
// correctly by checking computed values against scalar implementation.
template<const size_t rounds = 256ul>
void
test_avx512_mod_add()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  alignas(64) ff::ff_t arr0[8 * rounds];
  alignas(64) ff::ff_t arr1[8 * rounds];
  alignas(64) ff::ff_t computed_res[8 * rounds];
  alignas(64) ff::ff_t expected_res[8 * rounds];

  // generate some random Z_q elements
  for (size_t i = 0; i < 8 * rounds; i++) {
    arr0[i] = ff::ff_t::random();
    arr1[i] = ff::ff_t::random();
  }

  // compute modulo addition over Z_q, using scalar implementation
  for (size_t i = 0; i < 8 * rounds; i++) {
    expected_res[i] = arr0[i] + arr1[i];
  }

  // compute modulo addition over Z_q, using AVX512 implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 8;

    const ff::ff_avx512_t a{ arr0 + off };
    const ff::ff_avx512_t b{ arr1 + off };

    const ff::ff_avx512_t c = a + b;
    c.store(computed_res + off);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 8 * rounds; i++) {
    assert(computed_res[i] == expected_res[i]);
  }
}

// Ensure that vectorized u64 x u64 -> u128, multiplication using AVX512
// intrinsics, is correctly implemented, by checking computed results against
// scalar implementation.
template<const size_t rounds = 256ul>
void
test_avx512_full_mul()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis{};

  alignas(64) uint64_t arr0[8 * rounds];
  alignas(64) uint64_t arr1[8 * rounds];
  alignas(64) uint64_t computed_res_hi[8 * rounds];
  alignas(64) uint64_t computed_res_lo[8 * rounds];
  alignas(64) uint64_t expected_res_hi[8 * rounds];
  alignas(64) uint64_t expected_res_lo[8 * rounds];

  // generate some random u64s
  for (size_t i = 0; i < 8 * rounds; i++) {
    arr0[i] = dis(gen);
    arr1[i] = dis(gen);
  }

  // compute full multiplication of two u64s, resulting into high and low
  // 64 -bit halves
  for (size_t i = 0; i < 8 * rounds; i++) {
    const auto res = ff::full_mul_u64(arr0[i], arr1[i]);

    expected_res_hi[i] = res.first;
    expected_res_lo[i] = res.second;
  }

  // compute full mutliplication of two u64s, resulting into high and low
  // 64 -bit halves, using AVX512 implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 8;

    const auto a = _mm512_load_epi64(arr0 + off);
    const auto b = _mm512_load_epi64(arr1 + off);

    const auto res = ff::full_mul_u64x8(a, b);

    _mm512_store_epi64(computed_res_hi + off, res.first);
    _mm512_store_epi64(computed_res_lo + off, res.second);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 8 * rounds; i++) {
    assert(computed_res_hi[i] == expected_res_hi[i]);
    assert(computed_res_lo[i] == expected_res_lo[i]);
  }
}

// Test that vectorized ( using AVX512 ) modulo multiplication over Z_q is
// implemented correctly by checking computed values against scalar
// implementation.
template<const size_t rounds = 256ul>
void
test_avx512_mod_mul()
{
  static_assert(rounds > 0, "Round must not be = 0 !");

  alignas(64) ff::ff_t arr0[8 * rounds];
  alignas(64) ff::ff_t arr1[8 * rounds];
  alignas(64) ff::ff_t computed_res[8 * rounds];
  alignas(64) ff::ff_t expected_res[8 * rounds];

  // generate some random Z_q elements
  for (size_t i = 0; i < 8 * rounds; i++) {
    arr0[i] = ff::ff_t::random();
    arr1[i] = ff::ff_t::random();
  }

  // compute modulo multiplication over Z_q, using scalar implementation
  for (size_t i = 0; i < 8 * rounds; i++) {
    expected_res[i] = arr0[i] * arr1[i];
  }

  // compute modulo multiplication over Z_q, using AVX512 implementation
  for (size_t i = 0; i < rounds; i++) {
    const size_t off = i * 8;

    const ff::ff_avx512_t a{ arr0 + off };
    const ff::ff_avx512_t b{ arr1 + off };

    const ff::ff_avx512_t c = a * b;
    c.store(computed_res + off);
  }

  // finally ensure both implementations produce same result.
  for (size_t i = 0; i < 8 * rounds; i++) {
    assert(computed_res[i] == expected_res[i]);
  }
}

#endif

}
