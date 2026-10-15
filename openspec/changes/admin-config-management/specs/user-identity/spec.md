## MODIFIED Requirements

### Requirement: Stable identity
Система SHALL обеспечивать уникальность Yandex ID; роль SHALL определяться актуальной настройкой единственного администратора, а не сохраняться как независимое назначение.

#### Scenario: Concurrent sign-ins
- **WHEN** несколько запросов одновременно регистрируют одну identity
- **THEN** возвращается один пользователь без дубликатов

#### Scenario: Administrator sign-in
- **GIVEN** Yandex ID пользователя совпадает с актуальным ADMIN_YANDEX_ID
- **WHEN** он входит через Яндекс
- **THEN** он получает роль admin

#### Scenario: Stored role is stale
- **GIVEN** сохранённая роль пользователя admin, но его Yandex ID не совпадает с актуальным ADMIN_YANDEX_ID
- **WHEN** проверяются его полномочия
- **THEN** он не получает административный доступ

### Requirement: Trusted OAuth boundary
HTTP OAuth-транспорт SHALL проверять одноразовый state, привязанный к браузеру, использовать PKCE S256 и получать identity от Яндекса; клиент не может назначить себе роль.

#### Scenario: Invalid state
- **WHEN** callback содержит неверный либо отсутствующий state
- **THEN** вход отклоняется до создания сессии и обращения к token endpoint

#### Scenario: Callback replay
- **WHEN** повторно используется уже обработанный либо просроченный state
- **THEN** callback отклоняется без обмена кода

#### Scenario: PKCE verification
- **WHEN** сервер обменивает код Яндекса
- **THEN** он передаёт verifier, сохранённый для этой попытки входа, соответствующий ранее переданному S256 challenge

## ADDED Requirements

### Requirement: Server-side sessions
Сервис users SHALL создавать сессию на 24 часа после подтверждённого OAuth-входа; непрозрачный токен передаётся через HttpOnly SameSite=Lax cookie, в БД хранится только его хеш.

#### Scenario: Profile after sign-in
- **WHEN** браузер запрашивает GET /me с действующей cookie
- **THEN** возвращаются ID, Yandex ID, имя и актуальная роль пользователя без OAuth-токена и токена сессии

#### Scenario: Expired session
- **WHEN** срок сессии истёк, но TTL cleanup ещё не удалил запись
- **THEN** запрос профиля отклоняется с 401

#### Scenario: Logout
- **WHEN** браузер отправляет POST /auth/logout с корректным Origin
- **THEN** текущая сессия удаляется в БД и cookie очищается

#### Scenario: Cookie security
- **WHEN** callback настроен на HTTPS
- **THEN** cookie использует Secure и префикс __Host-
- **AND** незашифрованный HTTP разрешён только для localhost/loopback
