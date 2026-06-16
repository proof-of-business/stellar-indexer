# Implementation Plan: Economic Fact Engine

## Overview

Build a Rust library crate that computes economic facts (MVP: Revenue) from Stellar on-chain data. The implementation proceeds from project scaffolding through data types, HTTP client, aggregation logic, and the public entry point, with property-based tests wired in close to each component they validate.

## Tasks

- [ ] 1. Scaffold the library crate
  - [ ] 1.1 Convert binary crate to library crate in `Cargo.toml`
    - Replace `[dependencies]` section with all required dependencies:
      `reqwest = { version = "0.12", features = ["json"] }`,
      `tokio = { version = "1", features = ["full"] }`,
      `serde = { version = "1", features = ["derive"] }`,
      `serde_json = "1"`,
      `chrono = { version = "0.4", features = ["serde"] }`
    - Add `[lib]` section: `name = "economic_fact_engine"`, `path = "src/lib.rs"`
    - Add `[dev-dependencies]`: `proptest = "1"`, `wiremock = "0.6"`,
      `tokio = { version = "1", features = ["full"] }` (already in deps but needs test-util awareness)
    - Delete `src/main.rs`
    - _Requirements: all (prerequisite for compilation)_

- [ ] 2. Implement `error.rs` — `EngineError` enum
  - [ ] 2.1 Create `src/error.rs` with all 8 error variants
    - Define `EngineError` enum with variants: `InvalidWalletAddress(String)`,
      `InvalidTimeWindow(String)`, `MissingRequiredField(String)`,
      `UnsupportedFactType(String)`,
      `HorizonApiFailure { status: u16, message: String }`,
      `NetworkTimeout(String)`, `HorizonMaxRetriesExceeded(String)`,
      `InternalComputationFailure(String)`
    - Derive `Debug`, `Clone`; implement `std::error::Error`
    - Implement `Display` for each variant producing human-readable text ≤ 256 chars with no stack traces, file paths, or memory addresses
    - Add `Serialize`/`Deserialize` impls (or `#[serde(…)]` attributes) producing
      `{ "error_code": "SNAKE_UPPER_CASE", "message": "…" }` JSON
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [ ]* 2.2 Write property test for `EngineError` descriptions (Property 11)
    - **Property 11: All error descriptions are ≤ 256 characters and contain no sensitive data**
    - Instantiate all 8 variants with maximum-length string payloads
    - Assert `display_string.len() <= 256` for every variant
    - Assert display strings do NOT match: `at src/`, `/home/`, `/usr/`, `0x[0-9a-f]+`
    - **Validates: Requirements 5.1, 5.2**

- [ ] 3. Implement `types.rs` — data models and precision helpers
  - [ ] 3.1 Create `src/types.rs` with all public and internal types
    - Define `FactRequest` (`wallet_address: String`, `fact_type: String`, `window_days: u32`) with `Deserialize`
    - Define `FactResponse` (`fact: Fact`, `wallet_address: String`, `window_days: u32`, `computed_at: String`) with `Serialize + Deserialize`
    - Define `Fact` enum with `Revenue { value: String, currency: String }` variant;
      apply `#[serde(tag = "type", rename_all = "snake_case")]`; add custom serializer so `value` is always emitted as a JSON string token
    - Define `pub(crate)` Horizon response structs: `HorizonPageResponse`, `HorizonEmbedded`, `HorizonLinks`, `HorizonLink`
    - Define `pub(crate) struct PaymentOperation` with all fields matching Horizon JSON
    - _Requirements: 4.1, 4.2, 4.3, 7.1, 7.3_

  - [ ] 3.2 Implement `parse_stroop_amount` and `stroops_to_decimal_string` in `types.rs`
    - `parse_stroop_amount(s: &str) -> Option<i64>`: split on `.`, validate ≤ 7 decimal digits, reconstruct as `i64`; return `None` for null/missing/non-numeric/excess precision
    - `stroops_to_decimal_string(stroops: i64) -> String`: `whole = stroops / 10_000_000`, `frac = stroops % 10_000_000`; format as `"{}.{:07}"` using `frac.abs()`
    - _Requirements: 3.2, 4.3_

  - [ ] 3.3 Implement input validation logic in `types.rs` (or `lib.rs`, called from `compute_fact`)
    - Validate `wallet_address`: empty/whitespace → `MissingRequiredField`; not matching `^G[A-Z2-7]{55}$` → `InvalidWalletAddress`
    - Validate `fact_type`: empty/whitespace → `MissingRequiredField`; not `"revenue"` → `UnsupportedFactType`
    - Validate `window_days`: `0` → `InvalidTimeWindow`; `> 365` → `InvalidTimeWindow`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.8, 7.2_

  - [ ]* 3.4 Write property tests for input validation (Properties 1–3)
    - **Property 1: Valid requests are accepted without validation errors**
    - Generate valid 56-char G-addresses, `window_days` in `[1, 365]`, `fact_type = "revenue"`; assert no validation error
    - **Property 2: Invalid wallet addresses are rejected**
    - Generate strings that are NOT 56-char G-addresses (and non-empty); assert `InvalidWalletAddress`
    - **Property 3: Out-of-range time windows are rejected**
    - Generate integers outside `[1, 365]` (i.e., `0` and `> 365`); assert `InvalidTimeWindow`
    - **Validates: Requirements 1.1, 1.3, 1.5, 1.6**

  - [ ]* 3.5 Write property test for time window bound computation (Property 4)
    - **Property 4: Time window bounds are computed correctly**
    - For any `window_days` in `[1, 365]` and a fixed `now`, assert `window_start == now − Duration::days(window_days)` and `window_end == now`
    - **Validates: Requirements 1.7**

  - [ ]* 3.6 Write property test for `value` field JSON serialization (Property 10)
    - **Property 10: Computed value is always serialized as a JSON string**
    - Generate random `i64` stroop values (including `0` and `i64::MAX / 10_000_000`); serialize `Fact::Revenue`; parse JSON; assert `value` token is a JSON string, not a JSON number
    - **Validates: Requirements 4.3**

- [ ] 4. Checkpoint — compile cleanly
  - Ensure the crate compiles without errors after tasks 1–3. Run `cargo check`. Ask the user if questions arise.

- [ ] 5. Implement `transaction_processor.rs` — aggregation pipeline
  - [ ] 5.1 Create `src/transaction_processor.rs` with `TransactionProcessor::compute_revenue`
    - Define `pub struct TransactionProcessor;`
    - Implement `pub fn compute_revenue(ops: &[PaymentOperation], wallet: &str) -> Result<i64, EngineError>`
    - Pipeline: (1) filter `destination == wallet`; (2) filter `asset_code == "USDC"` AND `asset_issuer == Some(CANONICAL_USDC_ISSUER)`; (3) call `parse_stroop_amount` on each `amount` field, skip `None`; (4) fold with `checked_add`, returning `InternalComputationFailure` on overflow
    - Define `const CANONICAL_USDC_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8_

  - [ ]* 5.2 Write example-based unit tests for `compute_revenue`
    - Empty operation list → returns `0i64`
    - Single canonical USDC inbound payment with amount `"15432.5000000"` → returns `154325000000i64`
    - Self-payment (source == destination == wallet) with canonical USDC → included in total
    - Operation with `amount = None` alongside a valid operation → only valid op's amount returned
    - Outbound-only payment (destination ≠ wallet) → excluded; total is 0
    - _Requirements: 3.1, 3.5, 3.6, 3.7, 3.8_

  - [ ]* 5.3 Write property tests for `compute_revenue` (Properties 5–8)
    - **Property 5: Revenue aggregation is correct for all input sets**
    - Generate `Vec<PaymentOperation>` with controlled USDC/non-USDC ratio; assert sum equals expected stroop total of qualifying subset
    - **Property 6: Non-canonical and null-issuer assets are always excluded**
    - Generate operations with random `asset_code`/`asset_issuer` (including `None`); assert non-canonical contribute exactly 0 stroops
    - **Property 7: Self-payments are always included**
    - Generate canonical USDC operations where `source_account == to == wallet`; assert they appear in revenue total
    - **Property 8: Operations with invalid amounts are silently skipped**
    - Generate operation lists with mixed valid/null/non-numeric `amount` fields; assert result equals sum of valid-amount ops only
    - **Validates: Requirements 3.1, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8**

- [ ] 6. Implement `stellar_client.rs` — HTTP client with pagination and retry
  - [ ] 6.1 Create `src/stellar_client.rs` with `StellarClient` struct and `new` constructor
    - Define `pub struct StellarClient { http: reqwest::Client, base_url: String }`
    - `pub fn new(base_url: &str) -> Self`: build `reqwest::Client` with 30-second timeout; store `base_url`
    - Implement `fn backoff_duration(attempt: u32) -> std::time::Duration`: return `min(2u64.pow(attempt) seconds, 30 seconds)` — attempt 0 → 1s, 1 → 2s, 2 → 4s
    - _Requirements: 2.4, 6.2_

  - [ ] 6.2 Implement `fetch_page` and `fetch_page_with_retry` internal helpers
    - `async fn fetch_page(&self, url: &str) -> Result<HorizonPageResponse, EngineError>`:
      issue GET, map timeout errors to `NetworkTimeout`, non-2xx to `HorizonApiFailure { status, message }`, parse failure to `HorizonApiFailure { status: 0, … }`
    - `async fn fetch_page_with_retry(&self, url: &str) -> Result<HorizonPageResponse, EngineError>`:
      call `fetch_page`; on 429 or 5xx retry up to 3 additional times (4 total) with `backoff_duration` sleep between attempts; on non-retryable 4xx return immediately; after exhausting retries return `HorizonMaxRetriesExceeded`
    - Per-page retry counter is independent across pages
    - _Requirements: 2.3, 2.6, 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ] 6.3 Implement `fetch_payments` pagination loop
    - `pub async fn fetch_payments(&self, wallet: &str, window_start: DateTime<Utc>, window_end: DateTime<Utc>) -> Result<Vec<PaymentOperation>, EngineError>`
    - Construct initial Horizon URL: `{base_url}/accounts/{wallet}/payments?order=desc&limit=200`
    - Loop: call `fetch_page_with_retry`; collect records; stop if `_links.next` is absent OR any record's `created_at` is earlier than `window_start`; follow `_links.next.href` otherwise
    - Filter collected records to only those with `created_at` within `[window_start, window_end)`
    - Return empty `Vec` without error when no records match (including zero-history wallet)
    - _Requirements: 2.1, 2.2, 2.5_

  - [ ]* 6.4 Write wiremock-based example tests for `StellarClient`
    - Mock returning HTTP 408/timeout → assert `NetworkTimeout` returned
    - Mock returning empty `_embedded.records` → assert empty `Vec`, no error
    - Mock returning 4 consecutive 5xx → assert `HorizonMaxRetriesExceeded` after exactly 4 HTTP requests
    - Mock returning 1 success after 2 retryable failures → assert success and correct record count
    - _Requirements: 2.3, 2.4, 2.5, 6.1, 6.3_

  - [ ]* 6.5 Write property tests for retry behavior (Properties 13–14)
    - **Property 13: Non-retryable 4xx errors produce exactly one HTTP request**
    - Generate HTTP status codes in `[400, 499]` excluding 429; mock returns that code once; assert exactly 1 request and `HorizonApiFailure` result
    - **Property 14: Retryable errors exhaust retry budget before failing**
    - Mock returns 429 or 5xx for 4+ consecutive calls to same URL; assert exactly 4 HTTP requests made and `HorizonMaxRetriesExceeded` returned
    - **Validates: Requirements 6.1, 6.3, 6.4**

  - [ ]* 6.6 Write property test for pagination correctness (Req 2.2)
    - Use `proptest` to generate N pages (N in `[1, 20]`) with random records per page; wire wiremock to serve them with correct `_links.next` chain; assert all records collected and last page has no `next` link causing correct termination
    - _Requirements: 2.2_

- [ ] 7. Checkpoint — unit tests pass
  - Run `cargo test`. All non-integration tests should pass. Ask the user if questions arise.

- [ ] 8. Implement `lib.rs` — public entry point
  - [ ] 8.1 Create `src/lib.rs` wiring validation → fetch → aggregate → respond
    - Declare modules: `pub mod types; pub mod error; mod stellar_client; mod transaction_processor;`
    - Re-export: `pub use types::{FactRequest, FactResponse, Fact}; pub use error::EngineError;`
    - Implement `pub async fn compute_fact(request: FactRequest) -> Result<FactResponse, EngineError>`:
      1. Call validation logic on all `FactRequest` fields; return immediately on any error
      2. Compute `window_end = Utc::now()`, `window_start = window_end - Duration::days(request.window_days as i64)`
      3. Construct `StellarClient::new(HORIZON_BASE_URL)` (use `"https://horizon.stellar.org"` as default)
      4. Call `stellar_client.fetch_payments(&request.wallet_address, window_start, window_end)?`
      5. Call `TransactionProcessor::compute_revenue(&ops, &request.wallet_address)?`
      6. Convert stroop total to string via `stroops_to_decimal_string`
      7. Construct and return `FactResponse { fact: Fact::Revenue { value, currency: "USDC".into() }, wallet_address: request.wallet_address, window_days: request.window_days, computed_at: window_end.format("%Y-%m-%dT%H:%M:%SZ").to_string() }`
    - _Requirements: 1.1, 1.7, 4.1, 4.5_

- [ ] 9. Serde round-trip tests
  - [ ]* 9.1 Write property test for `FactResponse` round-trip (Property 9)
    - **Property 9: Fact_Response serialization round-trip**
    - Generate `FactResponse` with random valid `wallet_address`, `window_days`, `computed_at`, and `Fact::Revenue { value, currency }` fields
    - Assert `serde_json::from_str::<FactResponse>(&serde_json::to_string(&r).unwrap()).unwrap()` equals original `r` field-by-field
    - Assert `value` is preserved to all 7 decimal places; `computed_at` to second precision
    - **Validates: Requirements 4.2, 4.4**

  - [ ]* 9.2 Write property test for `Fact` enum round-trip (Property 15)
    - **Property 15: Existing fact variants round-trip through serde unchanged**
    - Generate `Fact::Revenue` with random `value` (7-decimal string) and `currency` fields
    - Serialize to JSON; deserialize; assert variant and all field values identical
    - Parse serialized JSON; assert `"type"` field equals `"revenue"`
    - **Validates: Requirements 7.1, 7.3**

  - [ ]* 9.3 Write property test for `UnsupportedFactType` without HTTP (Property 16)
    - **Property 16: Unknown fact types are rejected before any computation**
    - Generate non-empty strings `s` where `s != "revenue"`; build a `FactRequest` with `s` as `fact_type` and an otherwise valid request
    - Assert result is `Err(EngineError::UnsupportedFactType(_))`
    - Assert no HTTP requests were made (no wiremock server needed — the test verifies by checking the error is returned synchronously before any await)
    - **Validates: Requirements 7.2**

- [ ] 10. End-to-end integration smoke test
  - [ ] 10.1 Write an integration test calling `compute_fact` end-to-end with a wiremock Horizon mock
    - Spin up a `wiremock::MockServer`; register mocks for `GET /accounts/{wallet}/payments` returning two pages of canonical USDC `PaymentOperation` records and a final page with no `next` link
    - Construct a `FactRequest` with a valid wallet address, `fact_type = "revenue"`, and `window_days = 30`
    - Pass `HORIZON_BASE_URL` override pointing to the wiremock server (expose `StellarClient::new` or a `compute_fact_with_base_url` test helper)
    - Assert `FactResponse.fact` is `Fact::Revenue { value, currency: "USDC" }` where `value` equals the sum of all qualifying mock records formatted to 7 decimal places
    - Assert `FactResponse.wallet_address` and `FactResponse.window_days` match the request
    - Assert `FactResponse.computed_at` parses as a valid ISO 8601 UTC timestamp
    - _Requirements: 1.1, 2.1, 2.2, 3.1, 4.1, 4.2, 4.5_

- [ ] 11. Final checkpoint — all tests pass
  - Run `cargo test`. Ensure all tests (unit, property, integration) pass with no warnings treated as errors. Ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; all core functionality is in the non-starred tasks.
- Property test tasks each carry the canonical property number from the design document for traceability.
- `proptest` blocks should include a comment tag: `// Feature: economic-fact-engine, Property N: <title>`.
- The `CANONICAL_USDC_ISSUER` constant belongs in `transaction_processor.rs` and should be tested directly rather than duplicated.
- `src/main.rs` must be deleted in task 1.1 — the crate is library-only.
- For property tests that require a `StellarClient` with an injectable base URL, expose a `#[cfg(test)]` constructor or a test-only `compute_fact_with_client` helper so wiremock URLs can be injected without changing the public API.
- Checkpoints at tasks 4 and 7 are compile/test gates; task 11 is the final gate.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "3.1"] },
    { "id": 2, "tasks": ["2.2", "3.2", "3.3"] },
    { "id": 3, "tasks": ["3.4", "3.5", "3.6", "5.1"] },
    { "id": 4, "tasks": ["5.2", "5.3", "6.1"] },
    { "id": 5, "tasks": ["6.2"] },
    { "id": 6, "tasks": ["6.3"] },
    { "id": 7, "tasks": ["6.4", "6.5", "6.6", "8.1"] },
    { "id": 8, "tasks": ["9.1", "9.2", "9.3"] },
    { "id": 9, "tasks": ["10.1"] }
  ]
}
```
