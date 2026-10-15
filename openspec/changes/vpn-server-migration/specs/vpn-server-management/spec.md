## ADDED Requirements

### Requirement: Encrypted server registry
The system SHALL store VPN server connection settings in the VPN service database and SHALL encrypt SSH passwords with an externally held key. API responses SHALL NOT expose passwords or ciphertext.

#### Scenario: Read server metadata
- **WHEN** an administrator lists configured servers
- **THEN** connection metadata and password presence are returned without secrets

### Requirement: Stable generation routing
The system SHALL bind each issuance and operation to its server ID and SHALL preserve this binding when the default server changes.

#### Scenario: Revoke an old issuance
- **WHEN** the default server changes before an old generation is revoked
- **THEN** revocation still targets that generation's original server

### Requirement: Reissue migration
The system SHALL reissue active configurations on a verified target with new keys while retaining permanent config IDs and owners. The downloadable file SHALL switch only after successful provisioning and encrypted persistence.

#### Scenario: Target unavailable
- **WHEN** target provisioning fails
- **THEN** the current file remains selected and retry reuses the reserved target generation

#### Scenario: Source unavailable
- **WHEN** the source cannot be reached
- **THEN** target issuance may succeed while old-generation revocation remains unconfirmed

#### Scenario: Deletion races with migration
- **WHEN** revocation is requested before migration commits its generation switch
- **THEN** migration cannot restore downloadable active access and any provisioned target peer is queued for revocation

### Requirement: Explicit old-generation cleanup
The system SHALL track issuance progress separately from old-generation cleanup and SHALL require an explicit administrative cleanup request to revoke superseded generations.

#### Scenario: New file issued
- **WHEN** a target generation becomes the selected generation
- **THEN** the source generation is not reported as revoked without host confirmation

### Requirement: Idempotent transition from environment
The system SHALL provide an explicit resumable import of existing environment settings and stored config references without creating or revoking VPN peers.

#### Scenario: Repeated import
- **WHEN** the import is retried after interruption
- **THEN** it resumes without duplicate server records or changes to client files