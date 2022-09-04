//! The implementation of XXH3_64bits
//!
//! See "xxh3-64b-ref.c" in the "clean" C implementation for details.
// Specific file: https://github.com/easyaspi314/xxhash-clean/blob/master/xxh3-64b-ref.c
const std = @import("std");
const assert = std.debug.assert;

pub const HashResult = u64;

/// The minimum size of secrets
pub const SECRET_SIZE_MIN = 136;
const STRIPE_LEN = 64;
// nb of secret bytes consumed at each accumulation
const SECRET_CONSUME_RATE = 8;
const ACC_NB = STRIPE_LEN / @sizeOf(u64);
comptime {
    if (ACC_NB != 8) unreachable;
}

//
// public API
//

/// The XXH3_64 hash function with custom secret
///
/// NOTE: The length of the secret must be >= SECRET_SIZE_MIN
pub fn xxh3_64bits_withSecret(input: []const u8, secret: []const u8) HashResult {
    if (input.len <= MIDSIZE_MAX) {
        return hashShort(input, secret, 0);
    } else {
        return hashLong_64b(input, secret);
    }
}

/// The XXH3-64 non-seeded hash function.
///
/// input: The data to hash.
pub fn xxh3_64bits(input: []const u8) HashResult {
    return xxh3_64bits_withSeed(input, 0);
}

/// The XXH3-64 seeded hash function.
///
/// input: The data to hash.
/// seed:    A 64-bit value to seed the hash with.
pub fn xxh3_64bits_withSeed(input: []const u8, seed: u64) HashResult {
    if (input.len <= MIDSIZE_MAX) {
        return hashShort(input, &kSecret, seed);
    } else {
        return hashLong_64b_withSeed(input, seed);
    }
}

//
// implementation
//

/// Mixes up the hash to finalize
fn avalanche(original_hash: u64) HashResult {
    var hash = original_hash;
    hash ^= hash >> 37;
    hash *%= 0x165667919E3779F9;
    hash ^= hash >> 32;
    return hash;
}

//
// short inputs
//

/// Hashes zero-length keys.
fn hash_len_0(secret: []const u8, seed: u64) HashResult {
    var acc = seed;
    acc +%= PRIME64_1;
    acc ^= read64(secret[56..]);
    acc ^= read64(secret[64..]);
    return avalanche(acc);
}
/// Hashes short keys from 1 to 3 bytes.
fn hash_len_1to3(
    input: []const u8,
    secret: []const u8,
    seed: u64,
) HashResult {
    assert(input.len > 0 and input.len <= 3);
    const byte1 = input[0];
    const byte2 = if (input.len > 1) input[1] else input[0];
    const byte3 = input[input.len - 1];

    const combined = (@as(u32, byte1) << 16) | (@as(u32, byte2) << 24) | (@as(u32, byte3) << 0) | (@intCast(u32, input.len) << 8);
    var acc: u64 = (read32(secret) ^ read32(secret[4..]));
    acc +%= seed;
    acc ^= @as(u64, combined);
    acc *%= PRIME64_1;
    return avalanche(acc);
}

/// Hashes short keys from 4 to 8 bytes.
fn hash_len_4to8(
    input: []const u8,
    secret: []const u8,
    orig_seed: u64,
) HashResult {
    assert(input.len >= 4 and input.len <= 8);
    const input_hi: u32 = read32(input);
    const input_lo: u32 = read32(input[(input.len - 4)..]);
    const input_64 = @as(u64, input_lo) | (@as(u64, input_hi) << 32);
    var acc: u64 = read64(secret[8..]) ^ read64(secret[16..]);
    var seed: u64 = orig_seed ^ (@as(u64, swap32(@truncate(u32, orig_seed))) << 32);
    acc -%= seed;
    acc ^= input_64;
    // rrmxmx mix, skips XXH3_avalanche
    acc ^= rotl64(acc, 49) ^ rotl64(acc, 24);
    acc *%= 0x9FB21C651E98DF25;
    acc ^= (acc >> 35) +% @as(u64, input.len);
    acc *%= 0x9FB21C651E98DF25;
    acc ^= (acc >> 28);
    return acc;
}
/// Hashes short keys from 9 to 16 bytes.
fn hash_len_9to16(
    input: []const u8,
    secret: []const u8,
    seed: u64,
) HashResult {
    assert(input.len >= 9 and input.len <= 16);
    var input_lo: u64 = read64(secret[24..]) ^ read64(secret[32..]);
    var input_hi: u64 = read64(secret[40..]) ^ read64(secret[48..]);
    var acc = input.len;
    input_lo +%= seed;
    input_hi -%= seed;
    input_lo ^= read64(input);
    input_hi ^= read64(input[input.len - 8 ..]);
    acc +%= swap64(input_lo);
    acc +%= input_hi;
    acc +%= mul128_fold64(input_lo, input_hi);
    return avalanche(acc);
}

/// Hashes short keys that are less than or equal to 16 bytes.
fn hash_len_0to16(
    input: []const u8,
    secret: []const u8,
    seed: u64,
) HashResult {
    assert(input.len <= 16);
    return switch (input.len) {
        9...16 => hash_len_9to16(input, secret, seed),
        4...8 => hash_len_4to8(input, secret, seed),
        1...3 => hash_len_1to3(input, secret, seed),
        0 => hash_len_0(secret, seed),
        else => unreachable,
    };
}

//
// midsize inputs
//

/// The primary mixer for the midsize hashes
fn mix16B(
    input: []const u8,
    secret: []const u8,
    seed: u64,
) HashResult {
    var lhs = seed;
    var rhs = 0 -% seed;
    lhs +%= read64(secret);
    rhs +%= read64(secret[8..]);
    lhs ^= read64(input);
    rhs ^= read64(input[8..]);
    return mul128_fold64(lhs, rhs);
}

/// Hashes midsize keys from 9 to 128 bytes.
fn hash_len_17to128(
    input: []const u8,
    secret: []const u8,
    seed: u64,
) HashResult {
    assert(input.len >= 17 and input.len <= 128);
    var i: usize = ((input.len - 1) / 32);
    var acc: u64 = input.len *% PRIME64_1;
    while (i >= 0) {
        // i believe this is basically hashing from both ends...
        acc +%= mix16B(input[(16 * i)..], secret[(32 * i)..], seed);
        acc +%= mix16B(
            input[(input.len - (16 * (i + 1)))..],
            secret[((32 * i) + 16)..],
            seed,
        );
        // Avoid underflow
        if (i == 0) {
            break;
        } else {
            i -= 1;
        }
    }
    return avalanche(acc);
}

const MIDSIZE_MAX = 240;

/// Hashes midsize keys from 129 to 240 bytes.
fn hash_len_129to240(
    input: []const u8,
    secret: []const u8,
    seed: u64,
) HashResult {
    assert(input.len >= 129 and input.len <= 240);
    const MIDSIZE_STARTOFFSET = 3;
    const MIDSIZE_LASTOFFSET = 17;

    var acc: u64 = @as(u64, input.len) *% PRIME64_1;
    const nbRounds: usize = input.len / 16;
    {
        var i: usize = 0;
        while (i < 8) {
            acc +%= mix16B(input[(16 * i)..], secret[(16 * i)..], seed);
            i += 1;
        }
    }
    acc = avalanche(acc);
    {
        var i: usize = 8;
        while (i < nbRounds) {
            acc +%= mix16B(
                input[(16 * i)..],
                secret[(16 * (i - 8)) + MIDSIZE_STARTOFFSET ..],
                seed,
            );
            i += 1;
        }
    }
    // last bytes
    acc +%= mix16B(input[input.len - 16 ..], secret[SECRET_SIZE_MIN - MIDSIZE_LASTOFFSET ..], seed);
    return avalanche(acc);
}

/// Hashes a short (or "midsize") input, <= 240 bytes
fn hashShort(
    input: []const u8,
    secret: []const u8,
    seed: u64,
) HashResult {
    assert(input.len <= 240);
    if (input.len <= 16) {
        return hash_len_0to16(input, secret, seed);
    }
    if (input.len <= 128) {
        return hash_len_17to128(input, secret, seed);
    }
    return hash_len_129to240(input, secret, seed);
}

//
// larger keys
//

/// This is the main loop.
///
/// According to the C impl, "this is usually written in SIMD code."
fn accumulate_512_64b(
    acc: *[ACC_NB]u64,
    input: []const u8,
    secret: []const u8,
) void {
    var i: usize = 0;
    while (i < ACC_NB) {
        var input_val = read64(input[(8 * i)..]);
        acc[i] +%= input_val;
        input_val ^= read64(secret[(8 * i)..]);
        acc[i] +%= @truncate(u32, input_val) * (input_val >> 32);
        i += 1;
    }
}

/// Scrambles input.
///
/// This is usually written in SIMD code,
/// as it is usually part of the main loop.
fn scrambleAcc(acc: *[ACC_NB]u64, secret: []const u8) void {
    var i: usize = 0;
    while (i < ACC_NB) {
        acc[i] ^= acc[i] >> 47;
        acc[i] ^= read64(secret[(8 * i)..]);
        acc[i] *%= PRIME32_1;
        i += 1;
    }
}

/// Processes a full block.
///
/// Callced "XXH3_accumulate_64b" in C code
fn accumulate_64b(
    acc: *[ACC_NB]u64,
    input: []const u8,
    secret: []const u8,
    nb_stripes: usize,
) void {
    var n: usize = 0;
    while (n < nb_stripes) {
        accumulate_512_64b(acc, input[(n * STRIPE_LEN)..], secret[(8 * n)..]);
        n += 1;
    }
}

/// Combines two accumulators with two keys
fn mix2Accs(acc: *const [2]u64, secret: []const u8) u64 {
    return mul128_fold64(acc[0] ^ read64(secret), acc[1] ^ read64(secret[8..]));
}

/// Combines 8 accumulators with keys into 1 finalized 64-bit hash.
fn mergeAccs(
    raw_acc: *[ACC_NB]u64,
    key: []const u8,
    start: u64,
) HashResult {
    const acc = @ptrCast([*]const u64, raw_acc);
    var result64 = start;
    var i: usize = 0;
    while (i < 4) {
        result64 +%= mix2Accs(
            @ptrCast(*const [2]u64, acc + (2 * i)),
            key[16 * i ..],
        );
        i += 1;
    }
    return avalanche(result64);
}

/// Controls the long hash function. This is used for both XXH3_64 and XXH3_128.
fn hashLong_64b(
    input: []const u8,
    secret: []const u8,
) HashResult {
    assert(secret.len >= SECRET_SIZE_MIN);
    const nb_rounds = (secret.len - STRIPE_LEN) / SECRET_CONSUME_RATE;
    const block_len = STRIPE_LEN * nb_rounds;
    const nb_blocks = input.len / block_len;
    const nb_stripes = (input.len - (block_len * nb_blocks)) / STRIPE_LEN;
    var acc: [ACC_NB]u64 = .{
        PRIME32_3,
        PRIME64_1,
        PRIME64_2,
        PRIME64_3,
        PRIME64_4,
        PRIME32_2,
        PRIME64_5,
        PRIME32_1,
    };

    {
        var n: usize = 0;
        while (n < nb_blocks) {
            accumulate_64b(&acc, input[(n * block_len)..], secret, nb_rounds);
            scrambleAcc(&acc, secret[(secret.len - STRIPE_LEN)..]);
            n += 1;
        }
    }
    // last partial block
    accumulate_64b(&acc, input[(nb_blocks * block_len)..], secret, nb_stripes);

    // last stripe
    if (input.len % STRIPE_LEN != 0) {
        const p = input[(input.len - STRIPE_LEN)..];
        // Do not align on 8, so that the secret is different from the scrambler
        const XXH_SECRET_LASTACC_START = 7;
        accumulate_512_64b(&acc, p, secret[(secret.len - STRIPE_LEN - XXH_SECRET_LASTACC_START)..]);
    }

    const XXH_SECRET_MERGEACCS_START = 11;

    // converge into final hash
    return mergeAccs(&acc, secret[XXH_SECRET_MERGEACCS_START..], @as(u64, input.len) *% PRIME64_1);
}

/// Hashes a long input, > 240 bytes
fn hashLong_64b_withSeed(input: []const u8, seed: u64) HashResult {
    var secret: [SECRET_DEFAULT_SIZE]u8 = undefined;
    var i: usize = 0;
    while (i < (SECRET_DEFAULT_SIZE / 16)) {
        write64(secret[(16 * i)..], read64(kSecret[(16 * i)..]) +% seed);
        write64(secret[(16 * i) + 8 ..], read64(kSecret[(16 * i) + 8 ..]) -% seed);
        i += 1;
    }
    return hashLong_64b(input, &secret);
}

//
// boring hash constants
//

const PRIME32_1: u32 = 0x9E3779B1;
const PRIME32_2: u32 = 0x85EBCA77;
const PRIME32_3: u32 = 0xC2B2AE3D;

const PRIME64_1: u64 = 0x9E3779B185EBCA87;
const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME64_3: u64 = 0x165667B19E3779F9;
const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME64_5: u64 = 0x27D4EB2F165667C5;

const SECRET_DEFAULT_SIZE = 192;
const kSecret: [SECRET_DEFAULT_SIZE]u8 = .{
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,

    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};

// Support functions for C code (mostly bit manipulation)
//
// Most of these are super boring, because Zig includes these
// bit manipulations in the stdlib (or as intrinsics).
//
// I include these wrapper  for consistency with the C implementation :)

/// Calculates a 64-bit to 128-bit unsigned multiply,
/// then xor's the low bits of the product with
/// the high bits for a 64-bit result.
fn mul128_fold64(lhs: u64, rhs: u64) u64 {
    // Rely on zig for u128 multiply support
    //
    // The C implementation usually uses emulation of this,
    // however Zig has compiler support for u128
    //
    // Most architectures have a "multiply high" and "multiply low"
    // instructions so 128-bit multiply is extremely cheep with compiler support
    //
    // If architecture/compiler don't have these instructions,
    // then our emulation is not going to beat `compiler_rt`
    const product: u128 = @as(u128, lhs) * @as(u128, rhs);
    const low = @truncate(u64, product);
    const high = @truncate(u64, product >> 64);
    return low ^ high;
}

/// Portably reads a 32-bit little endian integer from p.
fn read32(bytes: []const u8) u32 {
    return std.mem.readIntSliceLittle(u32, bytes);
}

/// Portably reads a 64-bit little endian integer from p.
fn read64(bytes: []const u8) u64 {
    return std.mem.readIntSliceLittle(u64, bytes);
}

// Portably writes a 64-bit little endian integer to p.
fn write64(bytes: []u8, val: u64) void {
    std.mem.writeIntSliceLittle(u64, bytes, val);
}

/// 32-bit byteswap
fn swap32(x: u32) u32 {
    return @byteSwap(x);
}

/// 64-bit byteswap
fn swap64(x: u64) u64 {
    return @byteSwap(x);
}

fn rotl64(x: u64, amt: u32) u64 {
    return std.math.rotl(u64, x, amt);
}

test "verify xxhash3" {
    const PRIME64 = 0x9e3779b185ebca8d;
    const TEST_SEEDS: [2]u64 = .{ 0, PRIME64 };
    // test empty string
    {
        const expected_hashes: [2]u64 = .{ 0x776EDDFB6BFD9195, 0x6AFCE90814C488CB };
        for (expected_hashes) |expected_hash, i| {
            const actual_hash = xxh3_64bits_withSeed("", TEST_SEEDS[i]);
            try std.testing.expectEqual(expected_hash, actual_hash);
        }
    }
    // generate test data to match upstream C impl
    //
    // This is the same "test data" that has
    const TEST_DATA_SIZE = 2243;
    var test_data: [TEST_DATA_SIZE]u8 = undefined;
    {
        var byte_gen: u64 = PRIME32_1;
        var i: usize = 0;
        while (i < TEST_DATA_SIZE) {
            test_data[i] = @truncate(u8, byte_gen >> 56);
            byte_gen *%= PRIME64;
            i += 1;
        }
    }
    const test_expected = &[_][3]u64{
        // 1 -  3
        .{ 1, 0xB936EBAE24CB01C5, 0xF541B1905037FC39 },
        // 4 -  8
        .{ 6, 0x27B56A84CD2D7325, 0x84589C116AB59AB9 },
        // 9 - 16
        .{ 12, 0xA713DAF0DFBB77E7, 0xE7303E1B2336DE0E },
        // 17 - 32
        .{ 24, 0xA3FE70BF9D3510EB, 0x850E80FC35BDD690 },
        // 33 - 64
        .{ 48, 0x397DA259ECBA1F11, 0xADC2CBAA44ACC616 },
        // 65 - 96
        .{ 80, 0xBCDEFBBB2C47C90A, 0xC6DD0CB699532E73 },
        // 129-240
        .{ 195, 0xCD94217EE362EC3A, 0xBA68003D370CB3D9 },
        // one block, last stripe is overlapping
        .{ 403, 0x1B2AFF3B46C74648, 0xB654F6FFF42AD787 },
        // one block, finishing at stripe boundary
        .{ 512, 0x43E368661808A9E8, 0x3A865148E584E5B9 },
        // 2 blocks, finishing at block boundary
        .{ 2048, 0xC7169244BBDA8BD4, 0x74BF9A802BBDFBAE },
        // 3 blocks, finishing at stripe boundary
        .{ 2240, 0x30FEB637E114C0C7, 0xEEF78A36185EB61F },
        // 3 blocks, last stripe is overlapping
        .{ 2243, 0x62C631454648A193, 0x6CF80A4BADEA4428 },
    };
    for (test_expected) |data| {
        const len = @intCast(usize, data[0]);
        const expected_hashes: [2]u64 = .{ data[1], data[2] };
        const target_data = test_data[0..len];
        try std.testing.expectEqual(expected_hashes.len, TEST_SEEDS.len);
        for (TEST_SEEDS) |seed, i| {
            const actual_hash = xxh3_64bits_withSeed(target_data, seed);
            const expected_hash = expected_hashes[i];
            if (actual_hash != expected_hash) {
                std.debug.print("For seed={d} and len={}\n", .{ seed, len });
                @breakpoint();
                // std.debug.print("For test_data={X}\n", .{std.fmt.fmtSliceHexUpper(target_data)});
            }
            try std.testing.expectEqual(expected_hash, actual_hash);
        }
    }
}
