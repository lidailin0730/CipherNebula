#pragma once

#include <cstring>

#if defined __AVX2__ && USE_AVX2 != 0

#pragma message("Using AVX2 for Rescue permutation")
#include "ff_avx.hpp"

#elif defined __ARM_NEON && USE_NEON != 0

#pragma message("Using NEON for Rescue permutation")
#include "ff_neon.hpp"

#else

#include "ff.hpp"

#endif

// Rescue Permutation over prime field Z_q, q = 2^64 - 2^32 + 1
//
// Constants are taken from
// https://github.com/novifinancial/winterfell/blob/437dc08/crypto/src/hash/rescue/rp64_256/mod.rs#L252-L269
namespace rescue {

// Capacity portion of Rescue permutation state begins at index 0
constexpr size_t CAPACITY_BEGINS = 0ul;

// Capacity portion of Rescue permutation state spans over first four elements
// of the state i.e. starting at index 0 and ending at index 3.
constexpr size_t CAPACITY = 4ul;

// Rate portion of Rescue permutation state begins at index 4
constexpr size_t RATE_BEGINS = CAPACITY_BEGINS + CAPACITY;

// Rate portion of Rescue permutation state spans over last eight elements of
// the state i.e. starting at index 4 and ending at index 11.
constexpr size_t RATE = 8ul;

// Rescue permutation state is 12 elements wide where each index holds an
// element ∈ Z_q
constexpr size_t STATE_WIDTH = CAPACITY + RATE;

// Digest portion of Rescue permutation state begins at index 4
constexpr size_t DIGEST_BEGINS = RATE_BEGINS;

// Digest portion of Rescue permutation state spans over first four elements of
// the rate portion i.e. starting at index 4 and ending at index 7.
constexpr size_t DIGEST_WIDTH = 4ul;

// Rescue permutation requires application of 7 rounds to target 128 -bit
// security with 40% security margin
constexpr size_t ROUNDS = 7ul;

// S-Box power, taken from
// https://github.com/novifinancial/winterfell/blob/437dc08/crypto/src/hash/rescue/rp64_256/mod.rs#L45-L51
constexpr size_t ALPHA = 7ul;

// Inverse S-Box power, taken from
// https://github.com/novifinancial/winterfell/blob/437dc08/crypto/src/hash/rescue/rp64_256/mod.rs#L52-L53
constexpr size_t INV_ALPHA = 10540996611094048183ul;

// Precomputed Rescue MDS matrix, which is of dimension 12 x 12, taken from
// https://github.com/novifinancial/winterfell/blob/21173bd/crypto/src/hash/rescue/rp64_256/mod.rs#L415-L584
alignas(32) constexpr ff::ff_t MDS[STATE_WIDTH * STATE_WIDTH]{
  7ul,  23ul, 8ul,  26ul, 13ul, 10ul, 9ul,  7ul,  6ul,  22ul, 21ul, 8ul,

  8ul,  7ul,  23ul, 8ul,  26ul, 13ul, 10ul, 9ul,  7ul,  6ul,  22ul, 21ul,

  21ul, 8ul,  7ul,  23ul, 8ul,  26ul, 13ul, 10ul, 9ul,  7ul,  6ul,  22ul,

  22ul, 21ul, 8ul,  7ul,  23ul, 8ul,  26ul, 13ul, 10ul, 9ul,  7ul,  6ul,

  6ul,  22ul, 21ul, 8ul,  7ul,  23ul, 8ul,  26ul, 13ul, 10ul, 9ul,  7ul,

  7ul,  6ul,  22ul, 21ul, 8ul,  7ul,  23ul, 8ul,  26ul, 13ul, 10ul, 9ul,

  9ul,  7ul,  6ul,  22ul, 21ul, 8ul,  7ul,  23ul, 8ul,  26ul, 13ul, 10ul,

  10ul, 9ul,  7ul,  6ul,  22ul, 21ul, 8ul,  7ul,  23ul, 8ul,  26ul, 13ul,

  13ul, 10ul, 9ul,  7ul,  6ul,  22ul, 21ul, 8ul,  7ul,  23ul, 8ul,  26ul,

  26ul, 13ul, 10ul, 9ul,  7ul,  6ul,  22ul, 21ul, 8ul,  7ul,  23ul, 8ul,

  8ul,  26ul, 13ul, 10ul, 9ul,  7ul,  6ul,  22ul, 21ul, 8ul,  7ul,  23ul,

  23ul, 8ul,  26ul, 13ul, 10ul, 9ul,  7ul,  6ul,  22ul, 21ul, 8ul,  7ul,
};

// Precomputed Rescue round constants, used during first half of the
// permutation, taken from
// https://github.com/novifinancial/winterfell/blob/437dc08/crypto/src/hash/rescue/rp64_256/mod.rs#L721-L828
alignas(32) constexpr ff::ff_t RC0[ROUNDS * STATE_WIDTH]{
  13917550007135091859ul, 16002276252647722320ul, 4729924423368391595ul,
  10059693067827680263ul, 9804807372516189948ul,  15666751576116384237ul,
  10150587679474953119ul, 13627942357577414247ul, 2323786301545403792ul,
  615170742765998613ul,   8870655212817778103ul,  10534167191270683080ul,

  14572151513649018290ul, 9445470642301863087ul,  6565801926598404534ul,
  12667566692985038975ul, 7193782419267459720ul,  11874811971940314298ul,
  17906868010477466257ul, 1237247437760523561ul,  6829882458376718831ul,
  2140011966759485221ul,  1624379354686052121ul,  50954653459374206ul,

  16288075653722020941ul, 13294924199301620952ul, 13370596140726871456ul,
  611533288599636281ul,   12865221627554828747ul, 12269498015480242943ul,
  8230863118714645896ul,  13466591048726906480ul, 10176988631229240256ul,
  14951460136371189405ul, 5882405912332577353ul,  18125144098115032453ul,

  6076976409066920174ul,  7466617867456719866ul,  5509452692963105675ul,
  14692460717212261752ul, 12980373618703329746ul, 1361187191725412610ul,
  6093955025012408881ul,  5110883082899748359ul,  8578179704817414083ul,
  9311749071195681469ul,  16965242536774914613ul, 5747454353875601040ul,

  13684212076160345083ul, 19445754899749561ul,    16618768069125744845ul,
  278225951958825090ul,   4997246680116830377ul,  782614868534172852ul,
  16423767594935000044ul, 9990984633405879434ul,  16757120847103156641ul,
  2103861168279461168ul,  16018697163142305052ul, 6479823382130993799ul,

  13957683526597936825ul, 9702819874074407511ul,  18357323897135139931ul,
  3029452444431245019ul,  1809322684009991117ul,  12459356450895788575ul,
  11985094908667810946ul, 12868806590346066108ul, 7872185587893926881ul,
  10694372443883124306ul, 8644995046789277522ul,  1422920069067375692ul,

  17619517835351328008ul, 6173683530634627901ul,  15061027706054897896ul,
  4503753322633415655ul,  11538516425871008333ul, 12777459872202073891ul,
  17842814708228807409ul, 13441695826912633916ul, 5950710620243434509ul,
  17040450522225825296ul, 8787650312632423701ul,  7431110942091427450ul,
};

// Precomputed Rescue round constants, used during last half of the
// permutation, taken from
// https://github.com/novifinancial/winterfell/blob/437dc08/crypto/src/hash/rescue/rp64_256/mod.rs#L830-L929
alignas(32) constexpr ff::ff_t RC1[ROUNDS * STATE_WIDTH]{
  7989257206380839449ul,  8639509123020237648ul,  6488561830509603695ul,
  5519169995467998761ul,  2972173318556248829ul,  14899875358187389787ul,
  14160104549881494022ul, 5969738169680657501ul,  5116050734813646528ul,
  12120002089437618419ul, 17404470791907152876ul, 2718166276419445724ul,

  2485377440770793394ul,  14358936485713564605ul, 3327012975585973824ul,
  6001912612374303716ul,  17419159457659073951ul, 11810720562576658327ul,
  14802512641816370470ul, 751963320628219432ul,   9410455736958787393ul,
  16405548341306967018ul, 6867376949398252373ul,  13982182448213113532ul,

  10436926105997283389ul, 13237521312283579132ul, 668335841375552722ul,
  2385521647573044240ul,  3874694023045931809ul,  12952434030222726182ul,
  1972984540857058687ul,  14000313505684510403ul, 976377933822676506ul,
  8407002393718726702ul,  338785660775650958ul,   4208211193539481671ul,

  2284392243703840734ul,  4500504737691218932ul,  3976085877224857941ul,
  2603294837319327956ul,  5760259105023371034ul,  2911579958858769248ul,
  18415938932239013434ul, 7063156700464743997ul,  16626114991069403630ul,
  163485390956217960ul,   11596043559919659130ul, 2976841507452846995ul,

  15090073748392700862ul, 3496786927732034743ul,  8646735362535504000ul,
  2460088694130347125ul,  3944675034557577794ul,  14781700518249159275ul,
  2857749437648203959ul,  8505429584078195973ul,  18008150643764164736ul,
  720176627102578275ul,   7038653538629322181ul,  8849746187975356582ul,

  17427790390280348710ul, 1159544160012040055ul,  17946663256456930598ul,
  6338793524502945410ul,  17715539080731926288ul, 4208940652334891422ul,
  12386490721239135719ul, 10010817080957769535ul, 5566101162185411405ul,
  12520146553271266365ul, 4972547404153988943ul,  5597076522138709717ul,

  18338863478027005376ul, 115128380230345639ul,   4427489889653730058ul,
  10890727269603281956ul, 7094492770210294530ul,  7345573238864544283ul,
  6834103517673002336ul,  14002814950696095900ul, 15939230865809555943ul,
  12717309295554119359ul, 4130723396860574906ul,  7706153020203677238ul,
};

#if defined __AVX2__ && USE_AVX2 != 0

// Uses AVX2 vector instrinsics for raising four elements ∈ Z_q to their 7-th
// power, by using less multiplications, than one would do if done using
// standard exponentiation routine.
//
// Adapted from
// https://github.com/novifinancial/winterfell/blob/437dc08/math/src/field/f64/mod.rs#L74-L82
static inline ff::ff_avx_t
exp7(const ff::ff_avx_t v)
{
  const auto v2 = v * v;
  const auto v4 = v2 * v2;
  const auto v6 = v2 * v4;
  const auto v7 = v * v6;

  return v7;
}

#elif defined __ARM_NEON && USE_NEON != 0

// Uses NEON vector instrinsics for raising two elements ∈ Z_q to their 7-th
// power, by using less multiplications, than one would do if done using
// standard exponentiation routine.
//
// Adapted from
// https://github.com/novifinancial/winterfell/blob/437dc08/math/src/field/f64/mod.rs#L74-L82
static inline ff::ff_neon_t
exp7(const ff::ff_neon_t v)
{
  const auto v2 = v * v;
  const auto v4 = v2 * v2;
  const auto v6 = v2 * v4;
  const auto v7 = v * v6;

  return v7;
}

#else

// Raise an element ∈ Z_q to its 7-th power, by using less multiplications, than
// one would do if done using standard exponentiation routine.
//
// Adapted from
// https://github.com/novifinancial/winterfell/blob/437dc08/math/src/field/f64/mod.rs#L74-L82
static inline ff::ff_t
exp7(const ff::ff_t v)
{
  const auto v2 = v * v;
  const auto v4 = v2 * v2;
  const auto v6 = v2 * v4;
  const auto v7 = v * v6;

  return v7;
}

#endif

// Adapted from
// https://github.com/novifinancial/winterfell/blob/437dc08/crypto/src/hash/rescue/mod.rs#L17-L25,
// to perform cheaper exponentiation by a constant exponent, using lesser
// multiplications.
//
// Starting address of `base`, `tail` & `res` must be aligned to 32 -bytes
// boundary, otherwise program will panic !
template<const size_t m>
static inline void
exp_acc(const ff::ff_t* const base,
        const ff::ff_t* const tail,
        ff::ff_t* const __restrict res)
{
  std::memcpy(res, base, sizeof(ff::ff_t) * STATE_WIDTH);

  for (size_t i = 0; i < m; i++) {

#if defined __AVX2__ && USE_AVX2 != 0

#if defined __GNUC__
#pragma GCC unroll 3
#elif defined __clang__
#pragma clang loop unroll(enable)
#endif
    for (size_t j = 0; j < 3; j++) {
      const size_t off = j * 4;

      const ff::ff_avx_t t0{ res + off };
      const auto t1 = t0 * t0;
      t1.store(res + off);
    }

#else

#if defined __GNUC__
#pragma GCC unroll 12
#elif defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#pragma clang loop interleave(enable)
#endif
    for (size_t j = 0; j < STATE_WIDTH; j++) {
      res[j] = res[j] * res[j];
    }

#endif
  }

#if defined __AVX2__ && USE_AVX2 != 0

#if defined __GNUC__
#pragma GCC unroll 3
#elif defined __clang__
#pragma clang loop unroll(enable)
#endif
  for (size_t i = 0; i < 3; i++) {
    const size_t off = i * 4;

    const ff::ff_avx_t t0{ res + off };
    const ff::ff_avx_t t1{ tail + off };
    const auto t2 = t0 * t1;
    t2.store(res + off);
  }

#else

#if defined __GNUC__
#pragma GCC unroll 12
#elif defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#pragma clang loop interleave(enable)
#endif
  for (size_t i = 0; i < STATE_WIDTH; i++) {
    res[i] = res[i] * tail[i];
  }

#endif
}

// Applies substitution box on Rescue permutation state, by raising each element
// to its 7-th power.
//
// Starting address of the Rescue permutation state must be aligned to 32 -bytes
// boundary, otherwise program will panic !
static inline void
apply_sbox(ff::ff_t* const state)
{
#if defined __AVX2__ && USE_AVX2 != 0

#if defined __GNUC__
#pragma GCC unroll 3
#elif defined __clang__
#pragma clang loop unroll(enable)
#endif
  for (size_t i = 0; i < 3; i++) {
    const size_t off = i * 4;

    const ff::ff_avx_t t0{ state + off };
    const auto t1 = exp7(t0);
    t1.store(state + off);
  }

#elif defined __ARM_NEON && USE_NEON != 0

#if defined __GNUC__
#pragma GCC unroll 6
#elif defined __clang__
#pragma unroll 6
#endif
  for (size_t i = 0; i < 6; i++) {
    const size_t off = i * 2;

    const ff::ff_neon_t t0{ state + off };
    const auto t1 = exp7(t0);
    t1.store(state + off);
  }

#else

#if defined __GNUC__
#pragma GCC unroll 12
#elif defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#pragma clang loop interleave(enable)
#endif
  for (size_t i = 0; i < STATE_WIDTH; i++) {
    state[i] = exp7(state[i]);
  }

#endif
}

// Applies inverse substitution box on Rescue permutation state, by raising each
// element to its 10540996611094048183-th power, with lesser many
// multiplications.
//
// Adapted from
// https://github.com/novifinancial/winterfell/blob/437dc08/crypto/src/hash/rescue/rp64_256/mod.rs#L335-L369
//
// Starting address of the Rescue permutation state must be aligned to 32 -bytes
// boundary, otherwise program will panic !
static inline void
apply_inv_sbox(ff::ff_t* const state)
{
  alignas(32) ff::ff_t t1[STATE_WIDTH];
  alignas(32) ff::ff_t t2[STATE_WIDTH];

#if defined __AVX2__ && USE_AVX2 != 0

#if defined __GNUC__
#pragma GCC unroll 3
#elif defined __clang__
#pragma clang loop unroll(enable)
#endif
  for (size_t i = 0; i < 3; i++) {
    const size_t off = i * 4;

    const ff::ff_avx_t s0{ state + off };
    const auto s1 = s0 * s0;
    const auto s2 = s1 * s1;

    s1.store(t1 + off);
    s2.store(t2 + off);
  }

#else

#if defined __GNUC__
#pragma GCC unroll 12
#elif defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#pragma clang loop interleave(enable)
#endif
  for (size_t i = 0; i < STATE_WIDTH; i++) {
    t1[i] = state[i] * state[i];
    t2[i] = t1[i] * t1[i];
  }

#endif

  alignas(32) ff::ff_t t3[STATE_WIDTH];
  exp_acc<3>(t2, t2, t3);

  alignas(32) ff::ff_t t4[STATE_WIDTH];
  exp_acc<6>(t3, t3, t4);

  alignas(32) ff::ff_t t5[STATE_WIDTH];
  exp_acc<12>(t4, t4, t5);

  alignas(32) ff::ff_t t6[STATE_WIDTH];
  exp_acc<6>(t5, t3, t6);

  alignas(32) ff::ff_t t7[STATE_WIDTH];
  exp_acc<31>(t6, t6, t7);

#if defined __AVX2__ && USE_AVX2 != 0

#if defined __GNUC__
#pragma GCC unroll 3
#elif defined __clang__
#pragma clang loop unroll(enable)
#endif
  for (size_t i = 0; i < 3; i++) {
    const size_t off = i * 4;

    const ff::ff_avx_t s0{ t7 + off };
    const auto s1 = s0 * s0;
    const ff::ff_avx_t s2{ t6 + off };
    const auto s3 = s1 * s2;
    const auto s4 = s3 * s3;
    const auto s5 = s4 * s4;

    const ff::ff_avx_t s6{ t1 + off };
    const ff::ff_avx_t s7{ t2 + off };
    const auto s8 = s6 * s7;
    const ff::ff_avx_t s9{ state + off };
    const auto s10 = s8 * s9;

    const auto s11 = s5 * s10;
    s11.store(state + off);
  }

#else

#if defined __GNUC__
#pragma GCC unroll 12
#elif defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#pragma clang loop interleave(enable)
#endif
  for (size_t i = 0; i < STATE_WIDTH; i++) {
    const auto a0 = t7[i] * t7[i];
    const auto a1 = a0 * t6[i];
    const auto a2 = a1 * a1;
    const auto a3 = a2 * a2;

    const auto b0 = t1[i] * t2[i];
    const auto b1 = b0 * state[i];

    state[i] = a3 * b1;
  }

#endif
}

// Adds round constants to Rescue permutation state.
//
// Note this routine is used during the first half of Rescue permutation.
//
// Starting address of the Rescue permutation state must be aligned to 32 -bytes
// boundary, otherwise program will panic !
static inline void
add_rc0(ff::ff_t* const state, const size_t ridx)
{
  const size_t rc_off = ridx * STATE_WIDTH;

#if defined __AVX2__ && USE_AVX2 != 0

#if defined __GNUC__
#pragma GCC unroll 3
#elif defined __clang__
#pragma clang loop unroll(enable)
#endif
  for (size_t i = 0; i < 3; i++) {
    const size_t off = i * 4;

    const ff::ff_avx_t s0{ state + off };
    const ff::ff_avx_t s1{ RC0 + rc_off + off };
    const auto s2 = s0 + s1;
    s2.store(state + off);
  }

#elif defined __ARM_NEON && USE_NEON != 0

#if defined __GNUC__
#pragma GCC unroll 6
#elif defined __clang__
#pragma unroll 6
#endif
  for (size_t i = 0; i < 6; i++) {
    const size_t off = i * 2;

    const ff::ff_neon_t s0{ state + off };
    const ff::ff_neon_t s1{ RC0 + rc_off + off };
    const auto s2 = s0 + s1;
    s2.store(state + off);
  }

#else

#if defined __GNUC__
#pragma GCC unroll 12
#elif defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#pragma clang loop interleave(enable)
#endif
  for (size_t i = 0; i < STATE_WIDTH; i++) {
    state[i] = state[i] + RC0[rc_off + i];
  }

#endif
}

// Adds round constants to Rescue permutation state.
//
// Note this routine is used during the last half of Rescue permutation.
//
// Starting address of the Rescue permutation state must be aligned to 32 -bytes
// boundary, otherwise program will panic !
static inline void
add_rc1(ff::ff_t* const state, const size_t ridx)
{
  const size_t rc_off = ridx * STATE_WIDTH;

#if defined __AVX2__ && USE_AVX2 != 0

#if defined __GNUC__
#pragma GCC unroll 3
#elif defined __clang__
#pragma clang loop unroll(enable)
#endif
  for (size_t i = 0; i < 3; i++) {
    const size_t off = i * 4;

    const ff::ff_avx_t s0{ state + off };
    const ff::ff_avx_t s1{ RC1 + rc_off + off };
    const auto s2 = s0 + s1;
    s2.store(state + off);
  }

#elif defined __ARM_NEON && USE_NEON != 0

#if defined __GNUC__
#pragma GCC unroll 6
#elif defined __clang__
#pragma unroll 6
#endif
  for (size_t i = 0; i < 6; i++) {
    const size_t off = i * 2;

    const ff::ff_neon_t s0{ state + off };
    const ff::ff_neon_t s1{ RC1 + rc_off + off };
    const auto s2 = s0 + s1;
    s2.store(state + off);
  }

#else

#if defined __GNUC__
#pragma GCC unroll 12
#elif defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#pragma clang loop interleave(enable)
#endif
  for (size_t i = 0; i < STATE_WIDTH; i++) {
    state[i] = state[i] + RC1[rc_off + i];
  }

#endif
}

#if defined __AVX2__ && USE_AVX2 != 0

// Given a 256 -bit AVX2 register holding four elements ∈ Z_q, this routine
// accumulates all four lanes into each of four resulting lanes, over Z_q
//
// 0: a0, a1, a2, a3
// 1: a1, a2, a3, a0
// 2: a2, a3, a0, a1
// 3: a3, a0, a1, a2
//
// -------------------
//
// res: (a0+a1+a2+a3), (a0+a1+a2+a3), (a0+a1+a2+a3), (a0+a1+a2+a3)
//
// Resulting vector should hold same value ( ∈ Z_q ) on all of its lanes.
static inline ff::ff_avx_t
accumulate_lanes(const ff::ff_avx_t vec)
{
  const auto t0 = _mm256_permute4x64_epi64(vec.v, 0b00111001);
  const auto t1 = _mm256_permute4x64_epi64(t0, 0b00111001);
  const auto t2 = _mm256_permute4x64_epi64(t1, 0b00111001);

  const auto t3 = vec + ff::ff_avx_t{ t0 };
  const auto t4 = t3 + ff::ff_avx_t{ t1 };
  const auto t5 = t4 + ff::ff_avx_t{ t2 };

  return t5;
}

#endif

// Multiplies Rescue permutation state by MDS matrix
//
// Starting address of the Rescue permutation state must be aligned to 32 -bytes
// boundary, otherwise program will panic !
static inline void
apply_mds(ff::ff_t* const state)
{
  alignas(32) ff::ff_t tmp[STATE_WIDTH]{};

#if defined __AVX2__ && USE_AVX2 != 0

#if defined __clang__
#pragma clang loop unroll(enable)
#endif
  for (size_t i = 0; i < 3; i++) {
    const size_t soff = i * 4;

    const ff::ff_avx_t s0{ state + 0 };
    const ff::ff_avx_t s1{ state + 4 };
    const ff::ff_avx_t s2{ state + 8 };

    // ----------------------------------------------

    const size_t mdsoff0 = (soff + 0) * STATE_WIDTH;

    const ff::ff_avx_t mds0_0{ MDS + mdsoff0 + 0 };
    const ff::ff_avx_t mds0_1{ MDS + mdsoff0 + 4 };
    const ff::ff_avx_t mds0_2{ MDS + mdsoff0 + 8 };

    const auto t0_0 = s0 * mds0_0;
    const auto t0_1 = s1 * mds0_1;
    const auto t0_2 = s2 * mds0_2;

    const auto t0_3 = t0_0 + t0_1;
    const auto t0_4 = t0_2 + t0_3;

    const auto t0_5 = accumulate_lanes(t0_4);

    // ------------------------------------------------

    const size_t mdsoff1 = (soff + 1) * STATE_WIDTH;

    const ff::ff_avx_t mds1_0{ MDS + mdsoff1 + 0 };
    const ff::ff_avx_t mds1_1{ MDS + mdsoff1 + 4 };
    const ff::ff_avx_t mds1_2{ MDS + mdsoff1 + 8 };

    const auto t1_0 = s0 * mds1_0;
    const auto t1_1 = s1 * mds1_1;
    const auto t1_2 = s2 * mds1_2;

    const auto t1_3 = t1_0 + t1_1;
    const auto t1_4 = t1_2 + t1_3;

    const auto t1_5 = accumulate_lanes(t1_4);

    // -------------------------------------------------

    const size_t mdsoff2 = (soff + 2) * STATE_WIDTH;

    const ff::ff_avx_t mds2_0{ MDS + mdsoff2 + 0 };
    const ff::ff_avx_t mds2_1{ MDS + mdsoff2 + 4 };
    const ff::ff_avx_t mds2_2{ MDS + mdsoff2 + 8 };

    const auto t2_0 = s0 * mds2_0;
    const auto t2_1 = s1 * mds2_1;
    const auto t2_2 = s2 * mds2_2;

    const auto t2_3 = t2_0 + t2_1;
    const auto t2_4 = t2_2 + t2_3;

    const auto t2_5 = accumulate_lanes(t2_4);

    // -------------------------------------------------

    const size_t mdsoff3 = (soff + 3) * STATE_WIDTH;

    const ff::ff_avx_t mds3_0{ MDS + mdsoff3 + 0 };
    const ff::ff_avx_t mds3_1{ MDS + mdsoff3 + 4 };
    const ff::ff_avx_t mds3_2{ MDS + mdsoff3 + 8 };

    const auto t3_0 = s0 * mds3_0;
    const auto t3_1 = s1 * mds3_1;
    const auto t3_2 = s2 * mds3_2;

    const auto t3_3 = t3_0 + t3_1;
    const auto t3_4 = t3_2 + t3_3;

    const auto t3_5 = accumulate_lanes(t3_4);

    // -------------------------------------------------

    const auto res0 = _mm256_blend_epi32(t0_5.v, t1_5.v, 0b00001100);
    const auto res1 = _mm256_blend_epi32(res0, t2_5.v, 0b00110000);
    const auto res2 = _mm256_blend_epi32(res1, t3_5.v, 0b11000000);

    _mm256_store_si256((__m256i*)(tmp + soff), res2);
  }

#else

#if defined __clang__
#pragma clang loop unroll(enable)
#endif
  for (size_t i = 0; i < STATE_WIDTH; i++) {
    const size_t off = i * STATE_WIDTH;

#if defined __GNUC__
#pragma GCC unroll 12
#elif defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#pragma clang loop interleave(enable)
#endif
    for (size_t j = 0; j < STATE_WIDTH; j++) {
      tmp[i] = tmp[i] + state[j] * MDS[off + j];
    }
  }

#endif

  std::memcpy(state, tmp, sizeof(tmp));
}

// Apply single Rescue permutation round
static inline void
apply_round(ff::ff_t* const state, const size_t ridx)
{
  // first half
  apply_sbox(state);
  apply_mds(state);
  add_rc0(state, ridx);

  // second half
  apply_inv_sbox(state);
  apply_mds(state);
  add_rc1(state, ridx);
}

// Rescue Permutation of 7 rounds
static inline void
permute(ff::ff_t* const state)
{
  for (size_t i = 0; i < ROUNDS; i++) {
    apply_round(state, i);
  }
}

}
