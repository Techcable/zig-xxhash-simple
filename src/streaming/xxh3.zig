/// The state of an xxh3 hashing operation.
///
/// The fields of this structure should be considered private.
// See XXH3_state_t in C impl
pub const XXH3State = struct {
    ///  The 8 accumulators. See @ref XXH32_state_s::v and @ref XXH64_state_s::v
    acc: align(64) [8]u64,
    /// Used to store a custom secret generated from a seed
    seed: align(64) [8]u7 
}

/// Default size of the secret buffer (and @ref XXH3_kSecret).
///
/// This is the size used in @ref XXH3_kSecret and the seeded functions.
///
/// Not to be confused with @ref XXH3_SECRET_SIZE_MIN.
const XXH3_SECRET_DEFAULT_SIZE = 192;