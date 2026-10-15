## ADDED Requirements

### Requirement: Owner-scoped config list
The system SHALL expose GET /me/configs to authenticated users and SHALL derive ownership exclusively from the verified session. Only the owner's active configurations SHALL be returned.

#### Scenario: Different owners
- **WHEN** user A requests their configurations while user B also owns configurations
- **THEN** only user A's active configurations are returned

#### Scenario: No own active configurations
- **WHEN** an authenticated user has no active configurations
- **THEN** the response is HTTP 200 with an empty JSON array

### Requirement: Owner-scoped file download
The system SHALL allow downloading only the current file of an active configuration owned by the authenticated user. An administrative role SHALL NOT bypass ownership on these routes.

#### Scenario: Foreign configuration
- **WHEN** an authenticated user requests another owner's configuration ID
- **THEN** the response is HTTP 404 and no file or owner data is disclosed

#### Scenario: Revoked configuration
- **WHEN** a user requests a configuration whose revocation has started or completed
- **THEN** the response is HTTP 404 without configuration contents

#### Scenario: Own active configuration
- **WHEN** the owner downloads an active configuration with an available current-generation file
- **THEN** the response contains the decrypted .conf as an attachment with no-store caching

### Requirement: Trusted service identity
The system SHALL authenticate internal config requests and SHALL ignore browser-supplied identity headers when deriving the owner.

#### Scenario: Forged identity
- **WHEN** a user supplies a different owner ID in query parameters or headers
- **THEN** ownership remains bound to the user's verified session

#### Scenario: Missing session
- **WHEN** a request has no valid session
- **THEN** the public API returns HTTP 401