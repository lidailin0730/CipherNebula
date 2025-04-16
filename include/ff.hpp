#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <random>
#include <utility>


//定义了素数域Z_q上的基本算术操作，包括加法、乘法、除法、取反和指数运算。
//还提供了一个函数来执行64位无符号整数的全乘法

// Prime Field ( i.e. Z_q ) Arithmetic | q = 2^64 - 2^32 + 1
namespace ff {

// Prime Field Modulus
constexpr uint64_t Q = 0xffffffff00000001ul;

// Given two 64 -bit unsigned integer operands, this routine multiplies them
// such that high and low 64 -bit limbs of 128 -bit result in accessible.
//
// Note, returned pair holds high 64 -bits of result first and then remaining
// low 64 -bits are kept.
inline constexpr std::pair<uint64_t, uint64_t>
full_mul_u64(const uint64_t lhs, const uint64_t rhs)
{
#if defined __aarch64__ && __SIZEOF_INT128__ == 16
  // Benchmark results show that only on aarch64 CPU, if __int128 is supported
  // by the compiler, it outperforms `else` code block, where manually high and
  // low 64 -bit limbs are computed.

  using uint128_t = unsigned __int128;

  const auto a = static_cast<uint128_t>(lhs);
  const auto b = static_cast<uint128_t>(rhs);
  const auto c = a * b;

  return std::make_pair(static_cast<uint64_t>(c >> 64),
                        static_cast<uint64_t>(c));

#else
  // On x86_64 targets, following code block always performs better than above
  // code block - as per benchmark results.

  const uint64_t lhs_hi = lhs >> 32;
  const uint64_t lhs_lo = lhs & 0xfffffffful;

  const uint64_t rhs_hi = rhs >> 32;
  const uint64_t rhs_lo = rhs & 0xfffffffful;

  const uint64_t hi = lhs_hi * rhs_hi;   // high 64 -bits
  const uint64_t mid0 = lhs_hi * rhs_lo; // mid 64 -bits ( first component )
  const uint64_t mid1 = lhs_lo * rhs_hi; // mid 64 -bits ( second component )
  const uint64_t lo = lhs_lo * rhs_lo;   // low 64 -bits

  const uint64_t mid0_hi = mid0 >> 32;          // high 32 -bits of mid0
  const uint64_t mid0_lo = mid0 & 0xfffffffful; // low 32 -bits of mid0
  const uint64_t mid1_hi = mid1 >> 32;          // high 32 -bits of mid1
  const uint64_t mid1_lo = mid1 & 0xfffffffful; // low 32 -bits of mid1

  const uint64_t t0 = lo >> 32;
  const uint64_t t1 = t0 + mid0_lo + mid1_lo;
  const uint64_t carry = t1 >> 32;

  // res = lhs * rhs | res is a 128 -bit number
  //
  // assert res = (res_hi << 64) | res_lo
  const uint64_t res_hi = hi + mid0_hi + mid1_hi + carry;
  const uint64_t res_lo = lo + (mid0_lo << 32) + (mid1_lo << 32);

  return std::make_pair(res_hi, res_lo);

#endif
}

// An element of prime field Z_q | q = 2^64 - 2^32 + 1, with arithmetic
// operations defined over it
struct ff_t
{
  uint64_t v = 0ul;

  // Given a 64 -bit unsigned integer, this routine returns an element of Z_q,
  // where its value is kept in canonical representation.
  inline constexpr ff_t(const uint64_t a = 0ul)
  {
    const bool flg = a >= Q;
    const uint64_t t = a - flg * Q;
    v = t;
  }

  // Generate field element having canonical value 0
  static inline constexpr ff_t zero() { return ff_t{ 0ul }; }

  // Generate field element having canonical value 1
  static inline constexpr ff_t one() { return ff_t{ 1ul }; }

  // Addition over prime field, both input operands and result to stay in
  // canonical form
  inline constexpr ff_t operator+(const ff_t& rhs) const
  {
    const uint64_t t0 = this->v + rhs.v;

    const bool flg0 = this->v > UINT64_MAX - rhs.v;
    const uint64_t t1 = static_cast<uint64_t>(-static_cast<uint32_t>(flg0));
    const uint64_t t2 = t0 + t1;

    return ff_t{ t2 };
  }

  // Negation over prime field, such that both input operand and output are in
  // canonical form
  inline constexpr ff_t operator-() const
  {
    const uint64_t t = Q - this->v;
    return ff_t{ t };
  }

  // Subtraction over prime field, such that both input operands and output are
  // in canonical form
  inline constexpr ff_t operator-(const ff_t& rhs) const
  {
    const ff_t t = -rhs;
    return *this + t;
  }

  // Multiplication over prime field, such that both input operands and output
  // are in canonical form
  inline constexpr ff_t operator*(const ff_t& rhs) const
  {
    const auto res = full_mul_u64(this->v, rhs.v);
    const uint64_t res_hi = res.first;
    const uint64_t res_lo = res.second;

    const uint64_t c = res_hi & 0xfffffffful;
    const uint64_t d = res_hi >> 32;

    const uint64_t t2 = res_lo - d;
    const bool flg0 = res_lo < d;
    const uint64_t t3 = static_cast<uint64_t>(-static_cast<uint32_t>(flg0));
    const uint64_t t4 = t2 - t3;

    const uint64_t t5 = (c << 32) - c;
    const uint64_t t6 = t4 + t5;
    const bool flg1 = t4 > UINT64_MAX - t5;
    const uint64_t t7 = static_cast<uint64_t>(-static_cast<uint32_t>(flg1));
    const uint64_t t8 = t6 + t7;

    return ff_t{ t8 };
  }

  // Raises an element of Z_q to N -th power ( which is a 64 -bit unsigned
  // integer ), over prime field, using exponentiation by repeated squaring
  // rule. Note, both input element and output elements are kept in their
  // canonical form.
  //
  // Adapted from
  // https://github.com/itzmeanjan/secp256k1/blob/6e5e654/field/scalar_field.py#L117-L127
  inline constexpr ff_t operator^(const size_t n) const
  {
    const ff_t br[]{ ff_t::one(), *this };
    ff_t res = ff_t::one();

    for (size_t i = 0; i < 64; i++) {
      res = res * res;

      const size_t bidx = 63 - i;
      res = res * br[(n >> bidx) & 0b1ul];
    }

    return res;
  }

  // Multiplicative inverse over prime field
  //
  // Say input is a & return value of this function is b, then
  //
  // assert (a * b) % q == 1
  //
  // When input a = 0, multiplicative inverse can't be computed, hence return
  // value is 0.
  //
  // Adapted from
  // https://github.com/itzmeanjan/kyber/blob/3cd41a5/include/ff.hpp#L190-L216
  inline constexpr ff_t inv() const { return *this ^ (Q - 2); }

  // Division over prime field Z_q
  inline constexpr ff_t operator/(const ff_t& rhs) const
  {
    return (*this) * rhs.inv();
  }

  // Check equality of canonical values of two elements ∈ Z_q
  inline constexpr bool operator==(const ff_t& rhs) const
  {
    return !static_cast<bool>(this->v ^ rhs.v);
  }

  // Check inequality of canonical values of two elements ∈ Z_q
  inline constexpr bool operator!=(const ff_t& rhs) const
  {
    return !(*this == rhs);
  }

  // Generate a random element ∈ Z_q
  static inline ff_t random()
  {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis{ 0ul, Q - 1ul };

    return ff_t{ dis(gen) };
  }

  // Writes an element of Z_q to output stream
  inline friend std::ostream& operator<<(std::ostream& os, const ff_t& elm);
};

std::ostream&
operator<<(std::ostream& os, const ff_t& elm)
{
  return os << "Z_q(" << elm.v << ", " << Q << ")";
}

}
