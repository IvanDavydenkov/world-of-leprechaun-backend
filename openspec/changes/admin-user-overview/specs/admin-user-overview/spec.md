# Admin User Overview Delta

## ADDED Requirements

### Requirement: Administrative user array
GET /admin/users SHALL возвращать JSON-массив профилей только после проверки действующей сессии и актуальных прав admin.

#### Scenario: Anonymous request
- **WHEN** запрос выполняется без действующей сессии
- **THEN** возвращается 401 без пользовательских или VPN-данных

#### Scenario: Regular user request
- **WHEN** user запрашивает список пользователей
- **THEN** возвращается 403 до обращения к VPN-статистике

#### Scenario: Administrative response
- **WHEN** admin запрашивает страницу каталога
- **THEN** каждый элемент содержит id, yandex_id, display_name, role, created_at и VPN-сводку
- **AND** пустая страница возвращается как []

### Requirement: Complete catalog through pagination
Endpoint SHALL сохранять массив в теле и давать доступ ко всему каталогу через limit/after; по умолчанию limit=50, максимум 100.

#### Scenario: More users than one page
- **WHEN** после текущей страницы есть ещё пользователи
- **THEN** X-Next-Cursor содержит курсор продолжения
- **AND** последовательное чтение страниц позволяет получить весь каталог без ограничения первыми 50 записями

#### Scenario: Invalid pagination
- **WHEN** limit или cursor некорректен
- **THEN** возвращается 400

### Requirement: Config counts and details
VPN-сводка SHALL содержать число постоянных конфигов total/active/disabled/pending и массив id/name/status/version, включая удалённые записи.

#### Scenario: Deleted and intermediate records
- **GIVEN** есть один active, один deleted и один deleting конфиг
- **WHEN** запрашивается сводка
- **THEN** counts равен total=3, active=1, disabled=1, pending=1
- **AND** каждый конфиг представлен в массиве с точным состоянием

#### Scenario: Reactivation preserves config count
- **WHEN** deleted запись повторно активируется с новой выдачей
- **THEN** total не увеличивается
- **AND** version и status отражают новую выдачу

#### Scenario: No assigned configs
- **GIVEN** у пользователя никогда не было выдач
- **WHEN** VPN-сервис подтверждает пустой профиль
- **THEN** counts содержит нули, configs равен [], а трафик равен нулю

### Requirement: Lifetime traffic across generations
Система SHALL накапливать upload_bytes, download_bytes и total_bytes по всем управляемым конфигам и поколениям пользователя, включая deleted и заменённые выдачи; total_bytes равен сумме направлений.

#### Scenario: Directions from server counters
- **WHEN** peer показывает RX=100 и TX=200 на сервере
- **THEN** вклад в upload_bytes пользователя равен 100, в download_bytes равен 200, total_bytes равен 300

#### Scenario: Deleted config retains usage
- **WHEN** конфиг отозван и помечен deleted
- **THEN** ранее сохранённый трафик остаётся в сумме пользователя

#### Scenario: Reissued config retains history
- **WHEN** прежняя выдача израсходовала 300 байт, а новая 50 байт
- **THEN** их общий вклад равен 350 без повторного начисления прежней выдачи

### Requirement: Durable traffic accumulation
Система SHALL сохранять накопленные суммы и идентичность образцов/эпох, предотвращать двойное начисление, отрицательные приросты и откат baseline запоздавшими данными.

#### Scenario: Duplicate sample
- **WHEN** тот же образец обрабатывается повторно или параллельно
- **THEN** прирост учитывается один раз

#### Scenario: Runtime counter resets
- **WHEN** подтверждена новая эпоха либо счётчик уменьшился
- **THEN** сохранённый накопленный итог не уменьшается
- **AND** новые показания учитываются с новой baseline
- **AND** неизвестный пропущенный участок обозначается неполным покрытием

#### Scenario: Final sample unavailable
- **WHEN** перед отзывом не удалось получить заключительные показания
- **THEN** отзыв доступа не блокируется навсегда ради статистики
- **AND** сумма сохраняется с отметкой partial

### Requirement: Freshness and unavailable data
Сводка SHALL различать свежесть показаний и полноту истории, возвращать observed_since/updated_at и не подменять неизвестный расход нулём.

#### Scenario: Stale host data
- **WHEN** у незавершённой выдачи последний успешный опрос старше 120 секунд
- **THEN** сохранённые суммы возвращаются с freshness=stale

#### Scenario: Existing configs without samples
- **WHEN** конфиги известны, но показания ещё не получены
- **THEN** traffic содержит freshness=unavailable и null вместо неизвестных байтов

#### Scenario: VPN service unavailable
- **WHEN** admin подтверждён, но VPN-сервис недоступен
- **THEN** массив пользователей возвращается с vpn.availability=unavailable
- **AND** counts/configs/traffic недоступной сводки равны null

#### Scenario: Unknown historical traffic
- **WHEN** до начала мониторинга или во время сбоя есть невосстановимый участок
- **THEN** история не объявляется полной и содержит coverage=partial либо unknown

### Requirement: Service boundaries and secret exclusion
users SHALL получать VPN-сводки через один аутентифицированный пакетный запрос для ID страницы, без чтения чужой БД и SSH-опроса из HTTP-обработчика.

#### Scenario: Page aggregation
- **WHEN** запрашивается страница из 50 пользователей
- **THEN** users делает один пакетный запрос VPN-сводок, а не 50 отдельных вызовов

#### Scenario: Untrusted internal call
- **WHEN** внутренний endpoint вызывается без подтверждённой сервисной identity
- **THEN** VPN-статистика не выдаётся

#### Scenario: Safe response
- **WHEN** admin получает список
- **THEN** ответ не содержит приватных ключей, PSK, файлов конфигов, session/OAuth-токенов или SSH-credentials

### Requirement: Unassigned existing configs
Система SHALL обнаруживать существующие peer без владельца, хранить их с owner_id=null и не приписывать конфиги или расход пользователям автоматически.

#### Scenario: Discover an existing peer
- **WHEN** синхронизация обнаруживает ранее неизвестный peer
- **THEN** создаётся неназначенная запись с source=discovered
- **AND** существующий peer на VPN-хосте не изменяется
- **AND** запись не входит в сводку какого-либо пользователя

#### Scenario: Repeat discovery
- **WHEN** тот же peer обнаружен повторно
- **THEN** дубликат не создаётся, владелец и накопленный расход сохраняются

### Requirement: Assign with all known historical usage
Только admin SHALL назначать неназначенный конфиг существующему пользователю; вся доступная история расхода этого конфига SHALL включаться в сумму владельца, в том числе период до назначения.

#### Scenario: Transfer historical usage
- **GIVEN** неназначенный конфиг накопил 5 ГБ
- **WHEN** admin назначает его пользователю и затем конфиг расходует ещё 2 ГБ
- **THEN** вклад этого конфига в трафик пользователя равен 7 ГБ

#### Scenario: Repeated assignment
- **WHEN** повторяется назначение того же конфига тому же пользователю
- **THEN** история не копируется и расход не удваивается

#### Scenario: Concurrent assignment
- **WHEN** один неназначенный конфиг одновременно назначается разным пользователям
- **THEN** владельцем становится только один пользователь, другой запрос получает конфликт

#### Scenario: Initial runtime counters
- **WHEN** при первом импорте доступны ненулевые RX/TX
- **THEN** эти значения учитываются один раз как известный накопленный расход
- **AND** последующие опросы добавляют только новые приросты

#### Scenario: Missing earlier history
- **WHEN** расход до прежнего сброса счётчиков не сохранён
- **THEN** назначение не создаёт вымышленную историю и не улучшает coverage до complete

### Requirement: Imported config file availability
Система SHALL различать наличие peer и наличие исходного клиентского файла и показывать source/file_available в деталях конфигов.

#### Scenario: No private client file
- **WHEN** обнаруженный peer назначен пользователю без исходного файла
- **THEN** его конфиг и расход учитываются у пользователя
- **AND** file_available=false, скачивание отсутствующего файла не предлагается
- **AND** приватный ключ не восстанавливается из публичного
