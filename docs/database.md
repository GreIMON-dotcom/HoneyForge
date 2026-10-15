# База данных

Основное хранилище — PostgreSQL 16. Схему создают миграции Alembic из `backend/migrations/versions`; сервис `migrate` применяет их при каждом запуске Compose до старта сервера. Все отметки времени хранятся в UTC с часовым поясом.

## Схема

```mermaid
erDiagram
    users ||--o{ login_sessions : "сеансы"
    users ||--o{ deployments : "инициатор"
    honeypot_profiles ||--o{ honeypots : "шаблон"
    hosts ||--o{ honeypots : "размещение"
    hosts ||--o{ network_endpoints : "диапазон портов"
    honeypots ||--|| network_endpoints : "точка подключения"
    honeypots ||--o{ agents : "удостоверения"
    honeypots ||--o{ deployments : "история"
    honeypots ||--o{ deployment_logs : "шаги"
    deployments ||--o{ deployment_logs : "шаги"
    honeypots ||--o{ management_commands : "операции"
    honeypots ||--o{ telemetry_events : "события"
    agents ||--o{ telemetry_events : "источник"
    honeypots ||--o{ sessions : "сеансы клиентов"
    honeypots ||--o{ alerts : "оповещения"
    alert_rules ||--o{ alerts : "правило"
    honeypots ||--o{ alert_rules : "область действия"

    hosts {
        string id PK
        string name
        boolean approved
        string provisioning
        string controller_token_hash
        string network
        int max_instances
        float cpu_budget
        int memory_budget_mb
        int port_range_start
        int port_range_end
        datetime last_seen
        jsonb metrics
    }
    honeypot_profiles {
        string id PK
        string name UK
        jsonb spec
        int version
    }
    honeypots {
        string id PK
        string name UK
        string description
        jsonb tags
        string profile_id FK
        int profile_version
        jsonb overrides
        jsonb configuration
        string update_policy
        string host_id FK
        string desired_state
        string status
        datetime transition_at
        int generation
        int applied_generation
        jsonb runtime
        string ip_address
        datetime last_seen
        int queue_size
        string error
    }
    network_endpoints {
        string id PK
        string host_id FK
        string network
        string alias
        int internal_port
        int published_port
        string mode
        string honeypot_id FK
    }
    agents {
        string id PK
        string honeypot_id FK
        string host_id FK
        string token_hash
        boolean approved
        boolean retired
        datetime last_seen
    }
    deployments {
        string id PK
        string honeypot_id FK
        string host_id FK
        string profile_id FK
        string initiated_by FK
        string operation
        int generation
        string status
        string runtime_identifier
        string error_message
    }
    deployment_logs {
        int id PK
        string honeypot_id FK
        string deployment_id FK
        datetime timestamp
        string level
        string code
        jsonb details
    }
    telemetry_events {
        int id PK
        string event_uid
        string honeypot_id FK
        string agent_id FK
        string session_id
        datetime timestamp
        datetime received_at
        string source_ip
        int destination_port
        string protocol
        string event_type
        string severity
        jsonb payload
    }
```

Таблицы `users`, `login_sessions`, `sessions`, `management_commands`, `alert_rules`, `alerts` и `audit_logs` не изменились по сравнению с первой версией.

Таблица `source_geo` (миграция `a3c9e1b72d54`) — кэш классификации и необязательной геолокации адресов источников. Она не связана внешними ключами с телеметрией и не изменяет события: адрес, тип (`public`, `private`, `loopback`, `reserved`), код и название страны, город, координаты, источник данных, время обогащения и срок действия.

## Что изменила миграция `e7a4d2c91f30`

| Таблица | Изменение |
|---|---|
| `hosts` | Удалён столбец `service_type` (узел больше не привязан к одному типу сервиса). Добавлены хеш секрета контроллера, сеть, политика ёмкости, диапазон портов, время последнего отчёта и измерения |
| `honeypots` | Снято ограничение уникальности `host_id`: на узле может быть много экземпляров. Добавлены описание, теги, версия профиля, собственные настройки, снимок конфигурации, политика обновления, время начала операции, наблюдаемое состояние контейнеров, время изменения |
| `agents` | Агент привязан к экземпляру (`honeypot_id`), а не к узлу. Снято ограничение уникальности `host_id`. Добавлены признак вывода из эксплуатации и время создания |
| `deployments` | Добавлены вид операции и идентификатор контейнера; инициатор может отсутствовать |
| `network_endpoints` | Новая таблица точек подключения |
| `deployment_logs` | Новая таблица шагов развёртывания и операций |

Типы сервисов хранятся не в таблице, а в реестре кода: добавить тип может только разработчик вместе с эмулятором, и таблица, редактируемая из интерфейса, создавала бы ложное впечатление настраиваемости.

## Ограничения целостности

- `honeypots.name` и `honeypot_profiles.name` уникальны.
- `network_endpoints`: уникальны пара «узел, сеть, порт» и пара «узел, сеть, псевдоним»; у экземпляра ровно одна точка подключения.
- `telemetry_events`: уникальна пара «агент, идентификатор события» — основа устранения дублей при повторной передаче.
- `sessions`: уникальна пара «ловушка, идентификатор сеанса».
- Внешние ключи связывают экземпляр с профилем и узлом, поэтому используемый профиль и занятый узел нельзя удалить.

## Перенос данных из модели двух слотов

Миграция не удаляет строки из `telemetry_events`, `audit_logs`, `users`, `honeypot_profiles`, `alerts` и `sessions`.

1. Создаётся узел `lab-docker` с контроллером. Хеш секрета контроллера сервер записывает при следующем запуске из переменной `CONTROLLER_TOKEN`.
2. Каждая существующая ловушка сохраняет идентификатор и переносится на узел `lab-docker`. Её конфигурация становится снимком конфигурации профиля, поколение увеличивается на единицу, состояние становится `deploying` или `stopping` в зависимости от требуемого.
3. Для каждой ловушки резервируется точка подключения с портом профиля. Если две ловушки использовали один порт на разных узлах, вторая получает следующий свободный.
4. Агенты слотов помечаются как выведенные из эксплуатации и теряют доступ. Строки остаются, потому что на них ссылаются сохранённые события.
5. Незавершённые команды и развёртывания закрываются; прежние узлы-слоты удаляются.

После запуска контроллер создаёт для перенесённых ловушек контейнеры и новые удостоверения агентов. Обратная миграция не поддерживается: для возврата восстановите резервную копию. Порядок обновления описан в [инструкции по миграции](migration.md).

## Срок хранения

Фоновая задача сервера удаляет события, сеансы клиентов и записи журнала развёртываний старше `RETENTION_DAYS` дней, а также истёкшие сеансы входа. Удаление экземпляра удаляет его события, сеансы, команды, развёртывания, оповещения, точку подключения и удостоверения агентов; запись об удалении остаётся в аудите.
