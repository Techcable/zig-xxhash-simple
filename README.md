zig-xxhash-simple
=================
A simple implementation of [xxHash](https://cyan4973.github.io/xxHash/) in pure Zig.

It is pure Zig (and relatively simple). It is intended mostly for use in `comptime` contexts.

This is designed for simplicity. For performance, I would strongly prefer binding to the C implementation.

I use both libraries in my program. I use the C library at runtime and this library at `comptime`.


## Supported variants
For now, only some variants of the xxHash function are supported:

- [x] XXH3-64b 
- [ ] XXH3-128b 
- [ ] XXH64
- [ ] XXH32

The newer XXH3 variant is noticabely faster than the older algorithms, especially on small sets of data.

This implementation is not optimized. However, I use this library at `comptime`, so it's important I use the same alogrithm at compile time and runtime.

XXH64 and XXH32 are likely to be easier to implement, but I have not yet had the time.

## Credit
Based off the official specification [here](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md) and ported from the "clean" C impl [here](https://github.com/easyaspi314/xxhash-clean).

The license is the same as the, since it is a very direct port.