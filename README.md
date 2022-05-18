zig-xxhash-simple
=================
A simple implementation of [xxHash](https://cyan4973.github.io/xxHash/) in pure Zig.

Importantly, it includes an implementation of the newer XXH3 variant, which is noticably faster on small sets of data (and is not present in some older ports).

Based off the official specification [here](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md) and the "clean" C impl [here](https://github.com/easyaspi314/xxhash-clean).

This is a very simple implementation, avoiding performance tricks and SIMD (like the "clean" C impl I linked above).

It is intended mostly for used in `comptime` contexts and places where the full library would be overkill.

For performance, prefer binding to the C implementation (which should have much better performance).

I use both in my program. I use the C library at runtime and this library at `comptime`.

## TODO
Support other variants
- `XXH3_128`
- `XXH32`

Both `XXH64` and `XXH32` are correctly implemented already :)
