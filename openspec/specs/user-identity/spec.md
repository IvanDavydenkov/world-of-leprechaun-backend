# User Identity Specification

## Purpose
Публичная регистрация через Яндекс и роли. HTTP OAuth и сессии ещё не реализованы.

## Requirements

### Requirement: Public registration
Система SHALL разрешать регистрацию любого пользователя с подтверждённым Yandex ID без приглашений и назначать роль user.

#### Scenario: First sign-in
- **GIVEN** провайдер подтвердил непустой Yandex ID
- **WHEN** пользователь впервые входит
- **THEN** создаётся пользователь с ролью user

### Requirement: Stable identity
Система SHALL обеспечивать уникальность Yandex ID и сохранять роль существующего пользователя.

#### Scenario: Concurrent sign-ins
- **WHEN** несколько запросов одновременно регистрируют одну identity
- **THEN** возвращается один пользователь без дубликатов

#### Scenario: Administrator sign-in
- **GIVEN** существующий пользователь имеет роль admin
- **WHEN** он повторно входит
- **THEN** роль admin сохраняется

### Requirement: Trusted OAuth boundary
Будущий HTTP OAuth-транспорт SHALL проверять state и получать identity от Яндекса; клиент не может назначить себе роль.

#### Scenario: Invalid state
- **WHEN** callback содержит неверный либо отсутствующий state
- **THEN** вход отклоняется до создания сессии
