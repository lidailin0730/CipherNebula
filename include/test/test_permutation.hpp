#pragma once
#include "permutation.hpp"
#include <cassert>

// Test functional correctness of Rescue Prime implementation
namespace test_rphash {

// Check if α and inv_α are correctly valued, which are used for applying S-Box
// and Inverse S-Box during Rescue Permutation
inline void
test_alphas()
{
  const auto v = ff::ff_t::random();
  const auto v_alpha = v ^ rescue::ALPHA;
  const auto v_inv_alpha = v_alpha ^ rescue::INV_ALPHA;

  assert(v == v_inv_alpha);
}

// Check Rescue permutation using known answer test
//
// Test vector taken from
// https://github.com/novifinancial/winterfell/blob/21173bd/crypto/src/hash/rescue/rp64_256/tests.rs#L69-L105
inline void
test_permutation()
{
  constexpr ff::ff_t expected[]{
    11084501481526603421ul, 6291559951628160880ul, 13626645864671311919ul,
    18397438323058963117ul, 7443014167353970324ul, 17930833023906771425ul,
    4275355080008025761ul,  7676681476902901785ul, 3460534574143792217ul,
    11912731278641497187ul, 8104899243369883110ul, 674509706691634438ul,
  };
  alignas(32) ff::ff_t state[]{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

  rescue::permute(state);

  for (size_t i = 0; i < rescue::STATE_WIDTH; i++) {
    assert(state[i] == expected[i]);
  }
}

}
