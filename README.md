# provide-rust

Provide rust client library.

<!-- [![Test Status](https://github.com/rust-random/rand/workflows/Tests/badge.svg?event=push)](https://github.com/rust-random/rand/actions)
[![Crate](https://img.shields.io/crates/v/rand.svg)](https://crates.io/crates/rand)
[![Book](https://img.shields.io/badge/book-master-yellow.svg)](https://rust-random.github.io/book/)
[![API](https://img.shields.io/badge/api-master-yellow.svg)](https://rust-random.github.io/rand/rand)
[![API](https://docs.rs/rand/badge.svg)](https://docs.rs/rand)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.36+-lightgray.svg)](https://github.com/rust-random/rand#rust-version-requirements) -->

## Installation

Add this line to your application's Cargo.toml:

```
[dependencies]
provide-rust = "0.1.0"
```

## Development

Run `make integration` to run the tests.
<!-- 
To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org). -->

### WASM support

The WASM target `wasm32-unknown-unknown` is not _automatically_ supported by
`rand` or `getrandom`. To solve this, either use a different target such as
`wasm32-wasi` or add a direct dependency on `getrandom` with the `js` feature
(if the target supports JavaScript). See
[getrandom#WebAssembly support](https://docs.rs/getrandom/latest/getrandom/#webassembly-support).

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/provideplatform/provide-rust).

# License

Rand is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT), and
[COPYRIGHT](COPYRIGHT) for details.
