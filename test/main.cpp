#include "test/test_ff.hpp"
#include "test/test_permutation.hpp"
#include <iostream>

// main函数是程序的入口点
int main() {
  // 调用Rescue Prime字段运算的测试函数
  test_rphash::test_field_ops();
  std::cout << "[test] Rescue Prime field arithmetic\n";

  // 如果定义了AVX2指令集并且USE_AVX2不为0，则运行AVX2相关的测试
#if defined __AVX2__ && USE_AVX2 != 0
  test_rphash::test_avx_mod_add();
  test_rphash::test_avx_full_mul();
  test_rphash::test_avx_mod_mul();
  std::cout << "[test] AVX2 -based Rescue Prime field arithmetic\n";
#endif

  // 如果定义了AVX512F指令集，则运行AVX512相关的测试
#if defined __AVX512F__
  test_rphash::test_avx512_mod_add();
  test_rphash::test_avx512_full_mul();
  test_rphash::test_avx512_mod_mul();
  std::cout << "[test] AVX512 -based Rescue Prime field arithmetic\n";
#endif

  // 如果定义了ARM NEON指令集并且USE_NEON不为0，则运行NEON相关的测试
#if defined __ARM_NEON && USE_NEON != 0
  test_rphash::test_neon_mod_add();
  test_rphash::test_neon_full_mul();
  test_rphash::test_neon_mod_mul();
  std::cout << "[test] NEON -based Rescue Prime field arithmetic\n";
#endif

  // 调用Rescue Permutation的测试函数
  test_rphash::test_alphas();
  test_rphash::test_permutation();
  std::cout << "[test] Rescue Permutation\n";

  // 返回成功状态码
  return EXIT_SUCCESS;
}