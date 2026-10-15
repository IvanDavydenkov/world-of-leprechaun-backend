# Persistence Operations Specification

## Purpose
Хранилище MongoDB, жизненный цикл и проверки состояния.

## Requirements

### Requirement: Startup initialization
Каждый сервис SHALL проверять MongoDB и создавать индексы до запуска HTTP; при ошибке завершаться в пределах ограниченного таймаута.

#### Scenario: Unavailable database
- **WHEN** MongoDB недоступна при старте
- **THEN** сервис завершается с ненулевым кодом

### Requirement: Database indexes
База users SHALL обеспечивать уникальность yandex_id; vpn_configs SHALL иметь индекс owner_id, _id.

#### Scenario: Duplicate identity
- **WHEN** одновременно создаются записи с одинаковым yandex_id
- **THEN** индекс предотвращает дубликаты

### Requirement: Health checks
Сервисы SHALL предоставлять GET /healthz для liveness и GET /readyz для доступности MongoDB.

#### Scenario: Storage outage
- **WHEN** MongoDB становится недоступна после старта
- **THEN** /readyz возвращает 503 без подробностей подключения
- **AND** /healthz продолжает возвращать 200

### Requirement: Persistent local deployment
Compose SHALL запускать MongoDB с постоянным томом, отдельными пользователями баз и без опубликованного порта MongoDB.

#### Scenario: Recreate container
- **GIVEN** том mongo-data сохранён
- **WHEN** контейнер MongoDB пересоздаётся
- **THEN** данные и учётные записи сохраняются
- **AND** init-скрипт повторно не выполняется
