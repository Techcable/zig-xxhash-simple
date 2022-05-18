//! Main entry point for the xxhash-simple library
//!
//! Contains all supported of the hashing library
pub const xxh3_64b = @import("./xxh3_64b.zig");

pub const HashVariant = enum {
    xxh3_64b,
};

test "force usgae" {
    _ = xxh3_64b;
}
