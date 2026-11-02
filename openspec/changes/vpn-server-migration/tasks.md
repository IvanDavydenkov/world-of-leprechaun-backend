## 1. Спецификация
- [x] Уточнить сохранение действующих выдач A/B/C и повторное использование при возвращении.
- [x] Описать подготовку сервера/helper через сайт с проверкой доверенного SSH fingerprint.
- [x] Зафиксировать целевой API и DTO, статусы, идемпотентность, частичный успех.
- [x] Подготовить отдельный handoff для frontend и обозначить нереализованные API.
- [x] Проверить пакет OpenSpec: openspec validate vpn-server-migration --strict — valid.

## 2. Backend (реализовано локально; production не обновлён)
- [x] Модель server bindings/generation history/selected pointer, индексы, CAS, routing revision.
- [x] Dry-run/backup/checkpoint импорт существующих env и метаданных, без новых peer.
- [x] Динамические подключения по БД, секреты и закреплённые SSH ключи, без fallback на env.
- [x] Discovery, prepare/resume, атомарная установка/обновление versioned helper под lock.
- [x] Долговечные общие operations, polling/items/history, lease/fencing/retry и безопасные ошибки.
- [x] Одно действие switch: default + фиксированный план всех active configs.
- [x] Create/reuse/already_selected, сохранение старых выдач, возврат без смены ключей.
- [x] Отдельный server/all_servers revoke и адаптация существующего удаления ко всем поколениям.
- [x] Совместимость пользовательских DTO и counts, сохранение истории без повторного начисления.
- [x] Capabilities включать только после завершения schema/import и поддержки API.

## 3. Frontend (передать другому агенту)
- [ ] Обновить спецификацию frontend и реализовать совместимый расширенный реестр/форму.
- [ ] Prepare UI/steps/discovery selection, только server-confirmed ready.
- [ ] Routing + кнопка switch без обязательного выбора source/правки env/ручного helper.
- [ ] Общие async status/items/history, polling и повтор после сбоя/перезагрузки.
- [ ] Отдельный отзыв с явным подтверждением; прежние удаления предупреждают «на всех серверах».
- [ ] Обновление кэшей/версий пользовательских конфигов, без обещания автопереключения устройств.
- [ ] Ошибки/старый backend, секреты вне Redux/persistent storage, mobile-first UI.
- [ ] Typecheck, Vitest/RTL, production build и mobile/desktop проверка.

## 4. Приёмка backend/интеграции
- [x] A→B→A сохраняет A и B peers и использует прежний A generation/file.
- [x] A→B→C не требует source online; revoked binding получает новое поколение только при следующем явном выборе.
- [x] Missing peer/file/journal не скрывается под reused; target unreachable не переключает файл.
- [x] Prepare не меняет awg0.conf/clientsTable/peer, не отправляет пароль при key mismatch.
- [x] Таймауты/двойной клик/рестарт/конкурентные switch не дублируют выдачи.
- [x] Частичный результат не откатывает default/успехи, retry не отменяет более новый switch.
- [x] Гонки delete/revoke-all/create/reactivate/switch не восстанавливают удалённый доступ.
- [x] Только явный отзыв меняет active peer; server_in_use отклоняет запрос до изменений.
- [x] Недоступность source при revoke не даёт ложного deleted/succeeded.
- [x] Сессии/Origin/service-token/admin/owner checks на всех соответствующих маршрутах.
- [ ] Резервная копия production и согласованный тест на выделенных серверах до общего переключения.