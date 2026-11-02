# Целевой HTTP-контракт для backend и frontend

Статус: контракт реализован в текущем локальном backend; production требует отдельного rollout/импорта. Все URL относительно users API (production https://api.worldofleprechauns.ru). Только актуальная admin-сессия; credentials: include. Origin проверяется для POST/PATCH/PUT/DELETE. Внутренний VPN API требует service token и подтверждает роль через users. no-store; пароль/ciphertext/приватные файлы/PSK/сырые stdout-stderr SSH в DTO не входят. Существующие GET /me/configs и download остаются owner-only.

## 1. Реестр и создание
Сохраняются POST /admin/vpn-servers, GET /admin/vpn-servers, GET /admin/vpn-servers/{id}, PATCH /admin/vpn-servers/{id}. Список остаётся массивом, как сейчас. Целевое расширение POST позволяет не знать контейнер/порт заранее:
```json
{
  "name": "Riga 2",
  "ssh_address": "31.56.205.28:22",
  "ssh_username": "root",
  "password": "<password>",
  "ssh_host_fingerprint": "SHA256:<trusted-ed25519-fingerprint>",
  "public_host": "31.56.205.28"
}
```
Обязательны name, ssh_address, ssh_username, password и ровно одно из ssh_host_key / ssh_host_fingerprint. ssh_host_key — полный ED25519 key без комментария; fingerprint — SHA256 в точном формате. Оба одновременно отклоняются 400. Не путать server host public key и клиентский ключ пользователя. public_host необязателен только если из SSH hostname однозначно получается публичный host; иначе 400/public_host_required. Если уже известны public_endpoint, container, interface, старый POST с этими полями продолжает работать, но запись всё равно требует prepare. Согласованность public_host/public_endpoint проверяется.

POST — 201, Location на запись, revision=1. PATCH сохраняет текущую семантику expected_revision, пропущенный password сохраняется, null/пустой пароль/пустой PATCH/неизвестные поля запрещены. После появления выдач нельзя подменять identity установки (host key, контейнер, интерфейс) или public endpoint: 409/server_identity_locked, нужно создать новую запись. Обслуживание SSH credentials/SSH address той же установки разрешено с повторной проверкой. Backend не использует PATCH как миграцию конфигов.

Целевой пример GET записи (данные примера):
```json
{
  "id": "srv-b",
  "name": "Riga 2",
  "ssh_address": "31.56.205.28:22",
  "ssh_username": "root",
  "password_set": true,
  "ssh_host_key": null,
  "ssh_host_fingerprint": "SHA256:<trusted-ed25519-fingerprint>",
  "public_host": "31.56.205.28",
  "public_endpoint": null,
  "container": null,
  "interface": null,
  "revision": 1,
  "preparation_status": "not_prepared",
  "prepared_revision": null,
  "checked_at": null,
  "helper": null,
  "last_error_code": null,
  "last_operation_id": null,
  "is_default": false,
  "bindings_counts": {"active": 0, "revoked": 0, "pending": 0},
  "created_at": "2026-11-02T10:00:00Z",
  "updated_at": "2026-11-02T10:00:00Z"
}
```
preparation_status: not_prepared / preparing / needs_input / ready / failed / stale. ready означает успешную подготовку точной connection revision, а не обход блокировки РКН и не факт доступности VPN со всех пользовательских сетей. Изменения имени не обнуляют готовность. После подготовки helper={"version":"<release>","sha256":"<digest>"}, ssh_host_key закреплён, endpoint/container/interface заполнены. Ошибки подготовки не удаляют сервер или его bindings. bindings_counts — число текущих bindings, не пользователей и не исторических поколений.

## 2. Подготовка
POST /admin/vpn-servers/{id}/prepare
```json
{"expected_revision":1}
```
Обязателен Idempotency-Key (ASCII 1..128). Ответ 202 и Operation ниже; Location: /admin/vpn-server-operations/{operation_id}. Даже если задача быстрая, это async. Если связь/проверка не прошли, ошибка видна в операции, а не выдаётся готовность. Версионный конфликт до постановки — 409.

Steps для prepare: verify_host_key, authenticate, inspect_ubuntu, inspect_docker, discover_awg, install_helper, verify_helper. Step status: pending/running/succeeded/failed/skipped. Helper может быть already_current без переписывания файла. Установка/обновление не меняют peer или их файлы.

Если discovery неоднозначен, status=needs_input, preparation_status=needs_input; operation.details содержит только безопасные candidates:
```json
{"candidates":[{"candidate_id":"candidate-1","container":"amnezia-awg2","interface":"awg0","published_udp_ports":[48892]}],"required_fields":["candidate_id","udp_port"]}
```
POST /admin/vpn-server-operations/{operation_id}/resume с НОВЫМ Idempotency-Key:
```json
{"expected_revision":1,"selection":{"candidate_id":"candidate-1","udp_port":48892}}
```
Только для prepare/needs_input. Выбор должен входить в candidates; допускается public_host, если discovery запросил именно его через required_fields. Нельзя передать произвольную shell-команду/контейнер из вне списка. Перед применением кандидаты перепроверяются; изменилась установка — 409/discovery_changed. Повтор резюме с тем же ключом идемпотентен. Результат 202, та же operation_id. В других статусах 409/operation_not_resumable.

## 3. Текущий routing и одна кнопка
GET /admin/vpn-routing
```json
{"default_server_id":"srv-a","revision":3,"active_switch_operation_id":null,"features":{"prepare":true,"switch":true,"revoke":true}}
```
Поля features появляются только после полной готовности соответствующего backend/schema; 404 старого backend не подменять успешным состоянием. Во время активного switch операции блокируются backend согласно design, а не только кнопками UI.

POST /admin/vpn-switches с Idempotency-Key:
```json
{"target_server_id":"srv-b","expected_routing_revision":3}
```
Ответ 202 Operation; Location на общий status endpoint. source_server_id НЕ нужен. Это одно действие назначает default и переключает все глобально active конфиги на target, независимо от прежних выбранных серверов. Старые peer остаются active. Включать cleanup/revoke_old в запрос запрещено. Только подготовленные ready серверы. Целевой target может уже быть default: это позволяет довести смешанное состояние до target, с проверкой bindings; если всё уже выбрано, элементы already_selected.

Результаты item.action: created / reused / already_selected / null (ещё неизвестно/ошибка). reused сохраняет ключи и remote peer; already_selected не меняет version. Для отозванного binding создаётся новая generation, action=created. Прошлые peer source не проверяются как условие переключения. Повторное нажатие после неизвестного ответа повторяет ТОТ ЖЕ key/payload. Новый target — новый key и новый запрос после завершения предыдущего.

Во время partial/failed не происходит отката default или успешных элементов. UI явно показывает текущий default и результаты, а не пишет «все переключены». POST retry описан ниже. Для следующего переключения перечитать routing revision.

## 4. Явный отзыв
POST /admin/vpn-revocations с Idempotency-Key:
```json
{"scope":"server","server_id":"srv-a","all_configs":true}
```
или
```json
{"scope":"server","server_id":"srv-a","config_ids":["cfg-1","cfg-2"]}
```
или явное глобальное отключение:
```json
{"scope":"all_servers","config_ids":["cfg-1","cfg-2"]}
```
Выбор ровно одного из all_configs=true / config_ids (1..100 уникальных ID), scope=all_servers запрещает server_id; scope=server требует server_id. all_configs=true фиксирует долговечный снимок на старте. Любой недействительный/чужой ID отклоняет запрос целиком до изменений. Ответ 202 Operation. Для server scope requested_count — число выбранных bindings; для all_servers — число постоянных config_id, item содержит агрегат подтверждения всех его поколений.

scope=server отклоняется целиком 409/server_in_use, если сервер default, участвует в активном switch либо выбран любым затронутым config_id. Ничего автоматически не переключать взамен. После переключения с сервера отзыв его standby bindings не меняет выбранные файлы. scope=all_servers блокирует доступ немедленно и не объявляет deleted до подтверждения отзыва на всех хостах. Недоступный сервер возвращает поэлементную ошибку, не ложный успех. Из модалки switch этот endpoint НИКОГДА не вызывается автоматически.

Существующие DELETE/bulk-delete/revoke-all маршруты пользователей остаются и получают all_servers семантику. UI этих кнопок должен явно говорить «на всех серверах». Один отзыв не должен незаметно оставлять standby-ключи действующими.

## 5. Общий формат async-операций
GET /admin/vpn-server-operations/{operation_id}
```json
{
  "operation_id":"op-1",
  "kind":"switch",
  "status":"running",
  "phase":"processing",
  "target_server_id":"srv-b",
  "server_id":null,
  "routing_revision":4,
  "counts":{"requested_count":10,"succeeded_count":5,"failed_count":1,"pending_count":4,"skipped_count":0},
  "steps":[],
  "details":null,
  "error_code":null,
  "retryable":false,
  "created_at":"2026-11-02T10:00:00Z",
  "updated_at":"2026-11-02T10:00:10Z"
}
```
kind: prepare / switch / revoke. status: queued / running / needs_input / succeeded / partial / failed. queued/running — незавершённые; needs_input — пауза prepare, не успех и не обычный terminal error. succeeded/partial/failed — завершённые попытки; retryable выставляет backend. phase: planning / processing / waiting_input / finished. counts=null у prepare и при построении плана; steps=[] у switch/revoke, заполнены у prepare. Для prepare server_id заполнен, target_server_id/routing_revision=null. Для revoke server_id задан только в scope=server, target_server_id/routing_revision=null. Поля результата — явные null там, где неприменимы, не фиктивные 0.

После фиксации плана requested_count стабилен и равен succeeded+failed+pending+skipped. Нулевой план завершается succeeded. Удалённый после старта config помечается skipped/deleted_during_switch; не активируется вновь. Внутренние безопасные повторы transient ошибок возможны пока running, failed становится окончательным результатом только после исчерпания попытки. Счётчики считаются по серверному состоянию, а не числу обработанных UI-ответов.

GET /admin/vpn-server-operations/{id}/items?limit=50&after=<cursor>
```json
{"items":[{"item_id":"item-1","config_id":"cfg-1","user_id":"user-1","source_server_id":"srv-a","target_server_id":"srv-b","status":"succeeded","action":"reused","error_code":null,"attempts":1}],"next_cursor":null}
```
limit 1..100, after — непрозрачный cursor backend; стабильный порядок по item_id. item.status pending/running/succeeded/failed/skipped; source_server_id может быть null и показывает выбранный сервер НА СТАРТЕ, а не условие проверки source. Нет generation/private key/file/ciphertext в item DTO. У prepare items пустой, шаги читаются в основной операции. Список GET /admin/vpn-server-operations?limit=20&after=<cursor> возвращает {"items":[Operation],"next_cursor":null}, новейшие сначала со стабильным cursor; limit 1..100. Нужен для восстановления UI после перезагрузки.

POST /admin/vpn-server-operations/{id}/retry с Idempotency-Key и пустым JSON {} — 202, та же operation_id. Только terminal partial/failed с retryable=true; перепроверяются права и server/routing revisions. Успешные и skipped элементы не повторяются; поколения/idempotency на хосте сохраняются. prepare повторяет безопасные проверки до места сбоя. У switch после более нового переключения/другого default — 409/switch_superseded. Поле retryable в старом GET не отменяет проверку актуального routing при POST.

## 6. Ошибки и идемпотентность
HTTP problem: {"error":"<code>"}. 401 authentication_required, 403 admin_required/invalid_origin, 400 invalid_request/invalid_idempotency_key/public_host_required, 404 not_found, 409 revision_conflict/server_not_ready/server_busy/switch_in_progress/pending_config_operations/server_in_use/server_identity_locked/discovery_changed/operation_not_resumable/switch_superseded/idempotency_conflict, 503 dependency_unavailable. Поле error — стабильный код, не сообщение SSH. Сохранение intent предшествует SSH; 202 не означает успех удалённого действия.

Безопасные operation/item/step error_code: host_unreachable, host_key_mismatch, ssh_auth_failed, sudo_required, unsupported_os, docker_missing, awg_not_found, awg_unsupported, discovery_changed, helper_conflict, helper_install_failed, helper_verify_failed, helper_journal_missing, host_operation_unconfirmed, binding_missing_on_host, file_unavailable, storage_unavailable, revision_conflict, deleted_during_switch. Для неизвестного кода frontend показывает общий текст и код без вывода сырых логов.

Idempotency-Key имеет scope actor+route+resource. Тот же key и canonical payload возвращают ту же операцию, другой payload — 409. Resume и retry — самостоятельные idempotent команды, ключи не совпадают с начальной командой. Во время неизвестного результата/сетевого таймаута ключ не менять. Нет произвольных request_id, role, user_id или SSH-команд из браузера, влияющих на права/исполнение.

## 7. Совместимость пользовательских DTO
GET /me/configs остаётся массивом собственных active выбранных конфигов, текущие id/name/status/version/created_at/download_available/download_url сохраняются. После switch download выдаёт только selected_generation, старый URL с тем же config_id даёт текущий выбранный файл. История standby не делает дополнительные элементы пользовательского списка. Дополнительное поле server={"id":"srv-b","name":"Riga 2"} разрешено только как аддитивное расширение, не требуется frontend для скачивания. Чужие/удалённые конфиги по-прежнему 404.

В GET /admin/users counts.total считает config_id, а не bindings; switch pending не увеличивает total/pending, если выбранная старая выдача остаётся active. Имеющееся unavailable трафика не подменяется нулём. Операционные ошибки видны в отдельном Operation, а не через выдуманный deleted.
Операционная граница текущей реализации: история/планы control ограничены 14 MiB (503/storage_capacity до принятия нового намерения), детали и rollout — docs/vpn-server-switching.md. Во время активной host-операции любой PATCH сервера возвращает server_busy, включая имя; после завершения name-only PATCH сохраняет готовность.
