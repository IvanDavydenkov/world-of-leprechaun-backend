## ADDED Requirements

### Requirement: Admin server registry
The system SHALL allow only current administrators to create, list, read and patch VPN server records.

#### Scenario: Non-admin request
- **WHEN** a regular user accesses any server registry route
- **THEN** the request is rejected without returning server data

### Requirement: Encrypted credentials
The system SHALL persist SSH passwords encrypted with an externally configured key and SHALL omit plaintext and ciphertext from responses.

#### Scenario: Read created record
- **WHEN** an administrator reads a server record
- **THEN** the response indicates password_set without returning the password or encrypted bytes

### Requirement: Conditional partial updates
The system SHALL require expected_revision for PATCH and preserve omitted values.

#### Scenario: Stale update
- **WHEN** expected_revision does not match the stored revision
- **THEN** the server returns HTTP 409 without changing the record

#### Scenario: Omitted password
- **WHEN** a valid PATCH omits password
- **THEN** the existing encrypted password is preserved