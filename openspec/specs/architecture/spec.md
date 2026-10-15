# Architecture Specification

## Purpose
Определить границы двух микросервисов, направление зависимостей слоёв и правила владения данными MongoDB.

## Requirements

### Requirement: Independent services
Система SHALL содержать независимо собираемые Go-сервисы users и vpn-configs.

#### Scenario: Independent build
- **WHEN** собирается один сервис из его каталога
- **THEN** исходники другого сервиса не требуются

### Requirement: Clean architecture
Слои domain и application SHALL быть независимы от MongoDB, HTTP и внешних провайдеров; application определяет интерфейсы адаптеров.

#### Scenario: Replace storage
- **WHEN** меняется драйвер хранилища
- **THEN** доменные сущности не импортируют новый драйвер

### Requirement: Separate data ownership
Сервисы SHALL обращаться только к собственной базе MongoDB через отдельные учётные записи.

#### Scenario: Database isolation
- **GIVEN** стандартный Compose
- **WHEN** users подключается своей учётной записью
- **THEN** запись имеет readWrite только для users
- **AND** vpn-configs использует другую запись с readWrite только для vpn_configs
