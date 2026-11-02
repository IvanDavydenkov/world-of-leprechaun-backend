# Backend: подготовка и переключение VPN-серверов

Реализованы маршруты и DTO из openspec/changes/vpn-server-migration/api-contract.md. Пользовательский frontend реализуется отдельно. Изменение не задеплоено автоматически и не переключает реальные серверы при запуске приложения.

## Обычная работа через сайт
1. POST /admin/vpn-servers: SSH address, username/password, доверенный ED25519 fingerprint либо full public key, public_host. Контейнер/порт можно определить при подготовке.
2. POST /admin/vpn-servers/{id}/prepare с expected_revision и Idempotency-Key. Poll GET /admin/vpn-server-operations/{id}; при needs_input выбрать candidate/UDP и отправить resume.
3. GET /admin/vpn-routing, затем POST /admin/vpn-switches с target_server_id, expected_routing_revision и новым ключом идемпотентности.
4. Смотреть прогресс/страницы items; при частичном результате повторять через retry, не новый switch с прежним намерением. Старые peer не отзываются.
5. Возврат на прежний сервер использует сохранённую действующую выдачу. Новый сервер создаёт недостающие выдачи. Файлы в кабинете переключаются после успешной проверки/сохранения. Пользователям надо заново скачать и импортировать выбранные файлы.
6. Явный POST /admin/vpn-revocations scope=server отзывает только standby-выдачи указанного сервера. Default/выбранный сервер защищён server_in_use. scope=all_servers и существующие DELETE/bulk-delete/revoke-all отключают конфиг на всех серверах.

Аренда VPS и установка Amnezia остаются ручными. Поддержка версии AWG определяется установщиком: сейчас amneziawg-tools v3.1.20260812, Ubuntu, контейнерная установка /opt/amnezia/awg. При другой версии — безопасная ошибка awg_unsupported. Не отключать проверку SSH-ключа. Root либо достаточный noninteractive sudo необходимы для автоматической установки helper.

Helper 2.0.0 входит в binary через go:embed. Подготовка сверяет digest, не загружает код по введённому URL, сохраняет host journal и устанавливает файл атомарно. Известный helper предыдущего релиза обновляется; неизвестный чужой файл даёт helper_conflict. Неудачная health-проверка откатывает замену. Несовместимость контекста container/interface не допускает использования журнала другого binding. Смена имени сервера сохраняет ready; во время активной операции PATCH отклоняется server_busy, чтобы не потерять revision. Изменение identity/endpoint после появления выдач запрещено: новая установка — новая запись.

## Одноразовое обновление существующего production
До обновления: сделать и проверить backup MongoDB и отдельно сохранить текущий VPN_CONFIG_ENCRYPTION_KEY. Не генерировать новый ключ. Остановить старые users/vpn-configs API и worker; MongoDB оставить запущенной. Старый бинарник не использует новую distributed lease и не должен работать параллельно с импортом.

Новый API на базе с существующими конфигами автоматически НЕ переключает их и НЕ выбирает новый хост из env. До завершения импорта features.switch/revoke=false, изменяющие конфиги API возвращают 503/schema_migration_required; чтение и скачивание прежних файлов доступны. CRUD и подготовка серверов доступны, чтобы сформировать реестр. На пустой БД schema ready включается автоматически; первый switch на подготовленный сервер с нулевым планом выбирает default.

В образе VPN API есть /import-vpn-server. Он не подключается к VPN-хосту и не изменяет peer/файлы. Читает прежние VPN_HOST_ADDRESS/USERNAME/PASSWORD/PUBLIC_ENDPOINT, проверенный VPN_KNOWN_HOSTS_FILE, MONGO_URI/MONGO_DATABASE и прежний ключ шифрования. Выберите один вариант:

- --server-id <id>: явно сопоставить существующую запись прежнему env-хосту. Проверяются address, endpoint, container/interface и trusted key. Не подставлять сюда ID нового хоста.
- --create-server: явно создать или повторно использовать детерминированную запись Legacy VPN из env и ED25519 known_hosts (для незахешированного hostname). Один и тот же env не создаёт новые записи при повторе.

Без --apply выполняется dry-run. Пример для Docker Compose:
```bash
# После backup, остановки прежних API и сборки нового образа:
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml run --rm --no-deps --entrypoint /import-vpn-server vpn-configs --create-server
# Проверить отчёт server_id/accounts/configs_to_bind/operations_to_bind.
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml run --rm --no-deps --entrypoint /import-vpn-server vpn-configs --create-server --apply --confirm-workers-stopped
# Затем запуск нового users и vpn-configs:
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml up -d --no-build
```

Если запись Legacy VPN уже есть в реестре вручную, использовать --server-id, а не --create-server. Импорт идемпотентен, повторяется после сбоя; config_id/owner_id/Generation/Version/файл сохраняются. Частично применённый импорт оставляет schema ready=false до завершения. Вся информация о старых выдачах привязывается к исходному серверу, даже если он заблокирован и недоступен. Ключи не перегенерируются.

После импорта runtime не использует VPN_HOST_* и known_hosts env как fallback. Их можно убрать из рабочего окружения после проверки, сохранив резервную копию старых настроек. Мастер-ключ, MongoDB, OAuth, сервисный токен остаются в env. Ни импорт, ни запуск новой версии не запускают switch или revoke автоматически.

Перед включением UI проверить подготовку нового сервера и A→B→A на выделенных тестовых конфигax. Общий production switch — отдельное действие администратора на сайте. На дату реализации production-переключение и реальная установка нового helper этой версией не выполнялись.

## Хранение и эксплуатационные ограничения
Маршрутизация и долговечные планы сохраняются CAS в vpn_fleet; метаданные конфигов/история выдач остаются в config_accounts. MongoDB standalone поддерживается без replica set. Все изменения конфигов, серверов и worker используют общую возобновляемую lease vpn_locks; перед записями проверяется владение lease, потеря lease отменяет контекст; файлы хоста дедуплицируются журналом поколений. Запросы при занятой lease могут получить 409/server_busy: повторять безопасно с тем же ключом. Публичные status/list операции lease не ждут.

Для контроля BSON-лимита запись control ограничена 14 MiB: превышение возвращает 503/storage_capacity до принятия нового плана/намерения. История автоматически не удаляется. Для существенно больших каталогов/долгой истории понадобится разнесение планов/истории по документам с durable outbox; текущая версия рассчитана на небольшой сервис. В payload list/items используются cursor и limit до 100; пользовательские приватные файлы туда не включаются.

Потеря helper journal или отсутствие действующего peer/file даёт явную ошибку, а не скрытое восстановление/reused. Повтор не доказывает, что исчезнувший внешний peer можно восстановить без решения администратора. Сбор трафика не добавлен в этом изменении: unavailable сохраняется, история не удваивается при switch.

## Проверки
Go unit/HTTP/SSH fixture tests, реальные MongoDB integration tests и CLI import test работают на изолированных базах MONGO_TEST_URI. Python tests используют fake Docker и временную файловую систему; реальные peer не меняют. Embedded helper и deploy/amnezia/leprechaun_awg.py должны совпадать байт в байт. Docker runtime и реальный VPN handshake проверяются отдельно перед rollout.