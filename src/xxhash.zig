//! Main entry point for the xxhash-simple library
//!
//! Contains all supported of the hashing library
pub const xxh3_64b = @import("./xxh3_64b.zig");

pub const HashVariant = enum {
    xxh3_64b,
};

test "force usage" {
    _ = xxh3_64b;
}

test "comptime hash" {
    comptime {
        const text = "foo bar baz";
        _ = xxh3_64b.xxh3_64bits(text);
        // test larger
        _ = xxh3_64b.xxh3_64bits(text ** 20);
    }
}
