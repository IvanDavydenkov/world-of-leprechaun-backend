## ADDED Requirements

### Requirement: Two roles and one administrator
Система SHALL поддерживать только user и admin и определять единственного admin по подтверждённому Yandex ID, совпадающему с актуальным ADMIN_YANDEX_ID.

#### Scenario: Owner signs in
- **GIVEN** ADMIN_YANDEX_ID настроен
- **WHEN** Яндекс подтверждает совпадающий subject
- **THEN** пользователь получает полномочия admin

#### Scenario: Ordinary registration
- **WHEN** регистрируется любая другая подтверждённая identity
- **THEN** пользователь имеет полномочия user и ноль назначенных конфигов

#### Scenario: Missing administrator setting
- **WHEN** ADMIN_YANDEX_ID отсутствует
- **THEN** ни один пользователь не получает admin автоматически

#### Scenario: Administrator replacement
- **WHEN** оператор меняет ADMIN_YANDEX_ID
- **THEN** прежний admin не может выполнять новые административные операции со старой сессией

### Requirement: Administrative authorization
Система SHALL разрешать только admin просматривать каталог пользователей, создавать и отзывать конфиги других пользователей; отказ проверки полномочий запрещает операцию.

#### Scenario: User attempts management
- **WHEN** user вызывает создание, отзыв одного или всех конфигов
- **THEN** операция отклоняется до изменения БД и обращения к VPN-хосту

#### Scenario: Client supplies role
- **WHEN** клиент передаёт role=admin или недоверенный заголовок роли
- **THEN** эти данные не предоставляют административных полномочий
