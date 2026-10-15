## ADDED Requirements

### Requirement: Create exact number of new configs
POST /admin/users/{user_id}/configs SHALL принимать count — целое число от 1 до 20 — и создавать ровно столько новых конфигов для существующего пользователя при полном успехе.

#### Scenario: Add three configs
- **GIVEN** у пользователя уже два active конфига
- **WHEN** admin передаёт count=3
- **THEN** создаются три новые записи и выдачи
- **AND** после успеха active становится пять
- **AND** существующие неназначенные или deleted записи не используются вместо новых

#### Scenario: Invalid count
- **WHEN** count отсутствует, нецелый, строковый либо вне диапазона 1..20
- **THEN** возвращается 400 без создания намерений и обращения к хосту

### Requirement: Administrative mutation authorization
Все операции выдачи и удаления SHALL требовать действующую сессию, актуальные права admin и доверенный Origin; целевой пользователь проверяется до побочных эффектов.

#### Scenario: Regular user request
- **WHEN** user вызывает выдачу или удаление
- **THEN** возвращается 403 до изменения данных и SSH

#### Scenario: Unauthenticated request
- **WHEN** нет действующей сессии
- **THEN** возвращается 401

### Requirement: Single selected and all revocation
Система SHALL предоставлять DELETE /admin/users/{user_id}/configs/{config_id}, POST /admin/users/{user_id}/configs/bulk-delete с config_ids и DELETE /admin/users/{user_id}/configs для одного, выбранных и всех конфигов соответственно.

#### Scenario: Selected configs
- **WHEN** admin передаёт допустимый список принадлежащих пользователю config_ids
- **THEN** отзываются только указанные конфиги
- **AND** остальные конфиги пользователя сохраняют доступ

#### Scenario: Foreign ID in batch
- **WHEN** хотя бы один переданный config_id отсутствует либо принадлежит другому владельцу
- **THEN** весь запрос отклоняется с 404 до каких-либо отзывов

#### Scenario: Soft deletion
- **WHEN** сервер подтвердил отзыв peer
- **THEN** соответствующая запись помечается deleted
- **AND** история расхода и запись сохраняются

#### Scenario: Already deleted record
- **WHEN** запрашивается отзыв уже deleted записи
- **THEN** она считается успешно обработанной без восстановления peer

#### Scenario: Revoke all blocks new issuance
- **WHEN** принята операция отзыва всех
- **THEN** новые выдачи и активации получают 409 до её завершения
- **AND** ранее принятые незавершённые создания также охватываются отзывом

### Requirement: Durable batch idempotency
Запросы изменения SHALL требовать Idempotency-Key и долговечно сохранять состав операции; повтор одинакового запроса не создаёт новую пачку и не повторяет успешные элементы.

#### Scenario: Duplicate batch creation
- **WHEN** повторяется count=3 с тем же ключом
- **THEN** возвращается та же operation_id и используются прежние дочерние ID

#### Scenario: Key reused with different payload
- **WHEN** тот же ключ передан с другим count либо другим набором ID
- **THEN** возвращается 409 без новой операции

#### Scenario: Restart midway
- **WHEN** процесс перезапускается после части созданий
- **THEN** сохранённые намерения продолжаются с прежними generation_id и без дубликатов

### Requirement: Asynchronous operation result
Принятый запрос SHALL возвращать HTTP 202 с operation_id, status, kind и requested_count; GET статуса SHALL показывать результаты каждого элемента без секретов.

#### Scenario: Partial creation
- **WHEN** два из трёх конфигов созданы, а третий не подтверждён
- **THEN** родитель показывает partial с результатами всех трёх элементов
- **AND** успешные конфиги не удаляются автоматически
- **AND** повтор обрабатывает только незавершённый элемент после сверки удалённого состояния

#### Scenario: Unconfirmed deletion
- **WHEN** хост не подтвердил отзыв
- **THEN** элемент не считается успешным и запись не помечается deleted

#### Scenario: Empty full revocation
- **WHEN** у пользователя нет конфигов для отзыва
- **THEN** операция имеет requested_count=0 и status=succeeded без SSH-изменений
