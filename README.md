# provide-rust

Provide Rust client library.

## Installation

Add this line to your application's Cargo.toml:

```
[dependencies]
provide-rust = "0.1.0"
```

## Development

Installing `cargo-nextest` is required to run the tests. Install with `cargo install cargo-nextest`. Then, run `make integration` to run the tests. Installing the PRVD CLI is also recommended, depending on what is being developed or tested

## Testing

`./ops/run_integration_tests.sh`

| Environment Variables         |                                Description                                 |
| ----------------------------- | :------------------------------------------------------------------------: |
| TEST=_test_                   |          Test a specific endpoint, will take priority over SUITE           |
| SUITE=_suite_                 | Test a specific service, defaults to all services if TEST nor SUITE is set |
| CONTAINER*REGEX=\_identifier* |               Dump the docker logs for a specific container                |

| Flags                            |                                              Description                                              |
| -------------------------------- | :---------------------------------------------------------------------------------------------------: |
| --without-prvd-invocation        |                                  Run the tests without the PRVD CLI                                   |
| --with-registry-contract-address |                     Run the tests with a pre-configured registry contract address                     |
| --skip-startup                   |                        Run the tests without starting up the docker containers                        |
| --skip-baseline-startup          |                  Start the stack without starting up the baseline docker containers                   |
| --skip-shutdown                  |                       Run the tests without shutting down the docker containers                       |
| --skip-setup                     | Run the tests without running the baseline setup function required for the baseline integration suite |
