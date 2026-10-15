## ADDED Requirements

### Requirement: Trusted frontend origin
The system SHALL allow credentialed CORS only for FRONTEND_ORIGIN and SHALL reject other browser origins.

#### Scenario: Production preflight
- **WHEN** the configured frontend requests a PATCH preflight
- **THEN** the response permits the method and configured request headers without requiring a session

### Requirement: Safe frontend redirects
The system SHALL accept authentication redirects only to relative paths or the configured frontend origin.

#### Scenario: Untrusted redirect configuration
- **WHEN** a redirect points to a different origin
- **THEN** application startup rejects the configuration

### Requirement: JSON logout
The system SHALL return HTTP 204 after clearing a session when logout accepts application/json.

#### Scenario: Browser API logout
- **WHEN** the authenticated browser posts logout with JSON Accept
- **THEN** no cross-origin redirect is followed by the API client