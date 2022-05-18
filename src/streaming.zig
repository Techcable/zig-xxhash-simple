//! Streaming variants of the hash function
//!
//! According to the documentation "This method is slower than single-call functions, due to state management."
//!
//! Unlike the C library, state (including buffers)
//! for the hasher is allocated directly on the stack.
//!
//! If this is not desired, there are alternatives APIs to support
//! heap allocation.

pub const xxh3 = @import("./streaming/xxh3.zig");