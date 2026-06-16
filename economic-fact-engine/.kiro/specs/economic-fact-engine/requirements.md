# Requirements Document

## Introduction

The Economic Fact Engine is Layer 2 of Project Blueprint — a private economic infrastructure system. Its responsibility is to fetch raw transaction data from the Stellar blockchain and transform it into structured, verifiable economic facts that downstream layers (Credential Engine, ZK Proof Layer) can consume.

The MVP delivers a single economic fact: **Revenue** — the total USDC received by a given Stellar wallet over a configurable trailing time window. The engine must operate entirely on-chain data, produce deterministic results, and never expose raw transaction data to callers. Only the computed fact (a numeric value with provenance metadata) is returned.

The system is designed with forward compatibility in mind: future facts (customer count, activity score, treasury metrics) share the same pipeline structure and output schema.

---

## Glossary

- **Engine**: The Economic Fact Engine — this system.
- **Stellar_Client**: The component responsible for communicating with the Stellar Horizon API to retrieve transaction and payment records.
- **Transaction_Processor**: The component responsible for filtering and aggregating raw Stellar payment records into economic facts.
- **Fact**: A structured, computed economic assertion derived from on-chain data. Example: `{ "type": "revenue", "value": "15432.5000000", "currency": "USDC", "window_days": 30 }`.
- **Revenue_Fact**: The specific economic fact representing total USDC received by a wallet within a time window.
- **Wallet_Address**: A valid Stellar public key (G-address) — a 56-character base32-encoded string starting with `G`.
- **Time_Window**: A trailing duration in whole days used to bound fact computation. Example: 30 days means the period from (now − 30 days) to now (UTC).
- **USDC**: USD Coin — the stablecoin asset on Stellar identified by asset code `USDC` and canonical issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`.
- **Horizon_API**: The Stellar Foundation's public HTTP API for querying blockchain data.
- **Issuer**: The Stellar account that issued the USDC asset. Used to distinguish canonical USDC from other assets that share the code `USDC`.
- **Payment_Operation**: A Stellar operation of type `payment`, `path_payment_strict_send`, or `path_payment_strict_receive` that transfers an asset between accounts.
- **Fact_Request**: The input to the Engine containing a Wallet_Address, a fact type, and a Time_Window.
- **Fact_Response**: The output of the Engine containing a Fact and provenance metadata.

---

## Requirements

### Requirement 1: Accept and Validate Fact Requests

**User Story:** As a Credential Engine, I want to submit a wallet address and a time window to the Economic Fact Engine, so that I receive a computed economic fact for that wallet.

#### Acceptance Criteria

1. THE Engine SHALL accept a Fact_Request containing a Wallet_Address, a fact type, and a Time_Window expressed as a whole number of days greater than zero.
2. WHEN a Fact_Request is received with a missing or empty Wallet_Address field, THE Engine SHALL return a structured error with error code `MISSING_REQUIRED_FIELD`.
3. WHEN a Fact_Request is received with a Wallet_Address that is not a 56-character base32 string starting with `G`, THE Engine SHALL return a structured error with error code `INVALID_WALLET_ADDRESS`.
4. WHEN a Fact_Request is received with a missing or empty Time_Window field, THE Engine SHALL return a structured error with error code `MISSING_REQUIRED_FIELD`.
5. WHEN a Fact_Request is received with a Time_Window of zero or a negative number of days, THE Engine SHALL return a structured error with error code `INVALID_TIME_WINDOW`. Validation SHALL only be triggered upon receipt of a complete Fact_Request; partial or malformed requests that are missing core structure SHALL be handled by the `MISSING_REQUIRED_FIELD` error code rather than time window validation.
6. WHEN a Fact_Request is received with a Time_Window exceeding 365 days, THE Engine SHALL return a structured error with error code `INVALID_TIME_WINDOW`.
7. THE Engine SHALL treat the Time_Window as a trailing period ending at the current UTC timestamp at the moment the request is processed.
8. WHEN a Fact_Request is received with a missing or empty fact type field, THE Engine SHALL return a structured error with error code `MISSING_REQUIRED_FIELD`.

---

### Requirement 2: Fetch Stellar Transaction Data

**User Story:** As the Transaction Processor, I want the Stellar Client to retrieve all payment operations for a wallet within the requested time window, so that I have complete on-chain data to compute facts from.

#### Acceptance Criteria

1. WHEN a valid Fact_Request is received, THE Stellar_Client SHALL query the Horizon_API for all Payment_Operations where the destination account matches the specified Wallet_Address and the operation's ledger close time falls within the Time_Window.
2. WHEN the Horizon_API returns paginated results, THE Stellar_Client SHALL follow all pagination cursors until either all records have been retrieved or a record's ledger close time is earlier than the start of the Time_Window, whichever comes first.
3. IF the Horizon_API returns an HTTP 4xx or 5xx error response, THEN THE Stellar_Client SHALL return a structured error with error code `HORIZON_API_FAILURE` containing the HTTP status code.
4. IF the Horizon_API connection times out after 30 seconds, THEN THE Stellar_Client SHALL return a structured error with error code `NETWORK_TIMEOUT`.
5. WHEN the Wallet_Address has no transaction history on Stellar, THE Stellar_Client SHALL return an empty set of Payment_Operations without error.
6. WHEN the Horizon_API returns a response body that cannot be parsed as valid JSON or does not conform to the expected Horizon response schema, THE Stellar_Client SHALL return a structured error with error code `HORIZON_API_FAILURE`.

---

### Requirement 3: Compute the Revenue Fact

**User Story:** As a Credential Engine, I want the Engine to compute the total USDC received by a wallet over a time window, so that I can issue a Revenue Threshold Credential without accessing raw transaction data.

#### Acceptance Criteria

1. WHEN Payment_Operations have been retrieved, THE Transaction_Processor SHALL sum the destination amounts of all Payment_Operations where: (a) the destination asset code is `USDC`, (b) the destination asset issuer is `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`, and (c) the destination account matches the Wallet_Address in the Fact_Request. Negative amounts (representing refunds or chargebacks) SHALL be included in the sum, and the Revenue_Fact value SHALL always equal the arithmetic sum of all qualifying operation amounts, which may be negative.
2. THE Transaction_Processor SHALL preserve precision to exactly 7 decimal places during summation, consistent with Stellar's stroop precision, truncating (not rounding) any excess precision.
3. WHEN a Payment_Operation's destination asset code or issuer does not match canonical USDC, THE Transaction_Processor SHALL exclude that operation from the Revenue_Fact computation without error.
4. WHEN a Payment_Operation's asset issuer field is null or missing, THE Transaction_Processor SHALL treat that operation as non-USDC and exclude it from computation.
5. WHEN qualifying USDC Payment_Operations exist within the Time_Window, THE Transaction_Processor SHALL produce a Revenue_Fact whose value equals the arithmetic sum of all qualifying operation amounts. WHEN no qualifying USDC Payment_Operations exist within the Time_Window, THE Transaction_Processor SHALL produce a Revenue_Fact with a value of `0.0000000`.
6. IF the Wallet_Address is both the source and destination of a Payment_Operation (self-payment), THEN THE Transaction_Processor SHALL include that operation in the Revenue_Fact computation, as it represents an inbound credit to the wallet.
7. THE Transaction_Processor SHALL NOT include Payment_Operations where the Wallet_Address is the source account and the destination account is a different address.
8. WHEN a Payment_Operation has a null, missing, or non-numeric amount field, THE Transaction_Processor SHALL skip that operation and continue processing remaining operations without returning an error.

---

### Requirement 4: Return a Structured Fact Response

**User Story:** As a Credential Engine, I want to receive a machine-readable Fact_Response with provenance metadata, so that I can construct a verifiable credential without needing to re-query the blockchain.

#### Acceptance Criteria

1. WHEN a Revenue_Fact has been computed, THE Engine SHALL return a Fact_Response containing: the fact type (`"revenue"`), the computed value formatted to exactly 7 decimal places, the currency (`"USDC"`), the Wallet_Address, the Time_Window in days, and the UTC computation timestamp in ISO 8601 format (e.g., `2024-01-15T12:00:00Z`).
2. THE Engine SHALL serialize Fact_Response values to well-formed JSON that can be parsed by any RFC 8259-compliant JSON parser.
3. THE computed value in the Fact_Response SHALL be serialized as a JSON string (not a JSON number) to preserve exactly 7 decimal places without floating-point precision loss.
4. WHEN a Fact_Response is serialized to JSON and then deserialized back to a Fact_Response, each field SHALL be equal in type and value to the original — including the computed value to all 7 decimal places and the timestamp to second precision.
5. THE Engine SHALL NOT include raw Payment_Operation records, counterparty addresses, individual transaction amounts, or transaction IDs in the Fact_Response.

---

### Requirement 5: Handle Errors Uniformly

**User Story:** As a Credential Engine, I want all errors from the Economic Fact Engine to follow a consistent structure, so that I can handle failures programmatically without parsing free-text messages.

#### Acceptance Criteria

1. THE Engine SHALL represent all error conditions as a structured error type containing a distinct enumerated error code and a human-readable description of no more than 256 characters.
2. WHEN an error occurs, THE Engine SHALL NOT include stack traces, file-system paths, memory addresses, private key material, or raw wallet data in the error response.
3. THE Engine SHALL define the following distinct error codes: `INVALID_WALLET_ADDRESS`, `INVALID_TIME_WINDOW`, `MISSING_REQUIRED_FIELD`, `UNSUPPORTED_FACT_TYPE`, `HORIZON_API_FAILURE`, `NETWORK_TIMEOUT`, `HORIZON_MAX_RETRIES_EXCEEDED`, and `INTERNAL_COMPUTATION_FAILURE`.
4. EVERY failure condition that can occur during request processing SHALL map to exactly one of the defined error codes; no untyped or undocumented errors SHALL be returned to callers.

---

### Requirement 6: Horizon API Retry Behavior

**User Story:** As an operator, I want the Engine to recover from transient Horizon API failures automatically, so that brief network instability does not cause fact computation to fail.

#### Acceptance Criteria

1. WHEN the Horizon_API returns an HTTP 429 (rate limit) or 5xx (server error) response, THE Stellar_Client SHALL retry the same request up to 3 additional times (4 total attempts) before returning an error.
2. WHEN retrying, THE Stellar_Client SHALL wait 1 second before the first retry, 2 seconds before the second retry, and 4 seconds before the third retry (exponential backoff), with a maximum wait of 30 seconds per interval. For any retry attempt index outside the explicitly defined range of 1–3, THE Stellar_Client SHALL allow any wait time within the 30-second maximum interval.
3. WHEN all 3 retry attempts are exhausted and the Horizon_API has not returned a successful response, THE Stellar_Client SHALL return a structured error with error code `HORIZON_MAX_RETRIES_EXCEEDED`.
4. WHEN the Horizon_API returns an HTTP 4xx error other than 429, THE Stellar_Client SHALL NOT retry and SHALL return the error immediately with error code `HORIZON_API_FAILURE`.
5. THE retry counter SHALL reset independently for each paginated page request; a failure on page N SHALL trigger up to 3 retries for page N without affecting the retry budget of other pages.

---

### Requirement 7: Extensibility for Future Fact Types

**User Story:** As a future developer of the Credential Engine, I want the Economic Fact Engine's data model to support additional fact types beyond revenue, so that new economic facts can be added without breaking existing integrations.

#### Acceptance Criteria

1. THE Engine SHALL represent Fact types using an extensible tagged-union (enum) data model such that adding a new fact variant requires no changes to the serialization or schema of existing fact type variants.
2. WHEN a Fact_Request specifies a fact type that the Engine does not yet support, THE Engine SHALL generate a structured error with error code `UNSUPPORTED_FACT_TYPE` without performing any computation. THE Engine SHALL make a best-effort attempt to return this error to the caller; if the structured error response fails to be delivered, the correct error code generation is sufficient to satisfy this requirement.
3. THE Engine SHALL define the Fact schema such that each fact type variant is self-describing — every Fact value SHALL contain its own type identifier (e.g., `"revenue"`), a computed value, and a unit of measurement (e.g., `"USDC"`).
