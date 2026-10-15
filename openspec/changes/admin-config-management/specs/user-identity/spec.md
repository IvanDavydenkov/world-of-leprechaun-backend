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
