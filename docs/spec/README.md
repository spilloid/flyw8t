# Formal specifications

| Spec | Models | Status |
|---|---|---|
| [`JobDelivery.tla`](JobDelivery.tla) | One job between server and agent over channels that lose, duplicate and reorder messages, with disconnects, agent crashes (journal recovery), cancellation and both server deadlines. Invariants: at-most-once execution, no success without an execution, expired and pre-dispatch-cancelled jobs never run, an agent's "not started" is true, and terminal states are stable. | **Written, not yet model-checked.** TLC was not run when this spec was written (2026-10-29): running the downloaded Java runtime was not permitted in that session. Treat it as a design document until it has been checked. |

The same properties *are* checked by executed tests:

- `crates/flyw8t-agent/tests/model.rs`: property-based model test over the real journal and the real `decide` function. 400 cases per `cargo test`, 5,000 cases verified with `PROPTEST_CASES=5000`. It also checks liveness after a fault-free settle phase, which the TLA+ spec does not yet state.
- `flyw8t_domain::job` unit tests: exhaustive over every (state, report) pair.

## Running TLC

```sh
# Java 11+ and tla2tools.jar from https://github.com/tlaplus/tlaplus/releases
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -deadlock JobDelivery
```

`-deadlock` disables deadlock checking: `Lose`, `Connect` and `Disconnect` are always enabled, so the model never deadlocks, and a reported deadlock would mean the spec is malformed.

When this spec is first checked, record the result (distinct states, depth, TLC version, date) in the table above. If TLC finds a violation, reproduce it against the Rust code before changing either: the spec is a hand translation and can be wrong in its own right.
