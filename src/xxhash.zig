//! Main entry point for the xxhash-simple library
//!
//! Supports all four variants of the hashing library
pub const xxh3_64b = @import("./xxh3_64b.zig");

pub const HashVariant = enum {
    xxh3_64b,
};
