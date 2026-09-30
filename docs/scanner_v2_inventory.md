# Scanner v2: универсальная инвентаризация

## Статус реализации

Новый контур работает рядом с Camera Scanner v2, не заменяя его API.
Это рабочая реализация части большого плана, **не завершение всех M1–M7**.
Каталог типов оборудования не означает наличие детектора каждого типа.

| Часть плана | Реализовано | Что ещё требуется |
|---|---|---|
| Диапазоны | IPv4/IPv6, CIDR, диапазоны, исключения, TCP/UDP 1–65535 | Дополнительные sweep backend и приоритетный sweep |
| Выполнение | Отдельные durable-очереди discovery/identification/enrichment, backpressure, общие лимиты | Агенты и дополнительные backend |
| Идентификация | Баннеры, TLS, реестр port-independent проб | Остальные специализированные протоколы |
| Хранение | Отдельная SQLite, endpoint JSON, свидетельства, компактное покрытие | Нормализованные ресурсы/устройства, история изменений |
| Возобновление | Блоки, checkpoint каждого завершённого порта, leases/fencing, частичные успехи | Распределённая очередь и агенты |
| Web | API, экран заданий/сервисов, фильтр протокола, NDJSON | Представления хостов, устройств и изменений |
| Классификация | Консервативные продуктовые правила с основаниями | Полное покрытие каталога оборудования |
| Камеры | Старые API, авторизация, просмотр и захват сохранены | Универсальный media-adapter и миграция CameraResult |

## Интерфейс и включение

Экран: `/scanner-v2`, ссылка «Scanner v2 · Сервисы» в основном меню.
API: `/api/scanner/v2`; старые камеры: `/api/v2`.
Новый экран и API требуют роли администратора.

Запуск **сетевых заданий через API** по умолчанию выключен:

```bash
export IP2DOMAIN_SCANNER_V2_ENABLED=1
```

Установите переменную в окружении процесса приложения и перезапустите
приложение своим обычным способом. Сам рефакторинг сервис не перезапускает.

Каждое создание/возобновление требует `authorized: true`.
Это подтверждение оператора, не автоматическая проверка принадлежности сети.

Хранилище по умолчанию: `<путь основной БД>.inventory`.
Можно явно указать `IP2DOMAIN_INVENTORY_DB_PATH`.
Старая БД камер не мигрируется и не очищается.

### Профили

| Профиль | Порты | Действия |
|---|---|---|
| `inventory_safe` | Выбранные TCP | TCP connect и начальные баннеры |
| `full_tcp` | Все TCP 1–65535 | TCP connect и начальные баннеры |
| `deep_identification` | Выбранные TCP/UDP, включая 1–65535 | TLS и прикладные пробы с `active_consent` |
| `industrial_safe` | Выбранные TCP | TCP connect и баннеры, не промышленные команды |
| `medical_safe` | Выбранные TCP | TCP connect и баннеры, не медицинские команды |

Для **полного TCP с поиском RTSP на нестандартном порту** нужно выбрать:
`profile=deep_identification`, `tcp_ports=1-65535`, `active_consent=true`.
`full_tcp` сам по себе не включает активные RTSP-запросы.

Все профили осуществляют активные сетевые соединения. Название `safe` не
гарантирует безвредность для любого оборудования и не означает passive capture.
В IPv4 CIDR включены оба конца диапазона; исключайте адреса broadcast вашей сети.
Неопределённые, multicast и limited-broadcast адреса отклоняются.
Область — только числовые адреса, DNS-имена целей автоматически не расширяются.

## CLI

```bash
# Ничего не сканирует: фактические возможности и доступность Nmap.
.venv/bin/python -m ip2domain.scanning.cli capabilities

# Только на разрешённом стенде: поиск RTSP/HTTP на всех TCP-портах.
.venv/bin/python -m ip2domain.scanning.cli --db ./scanner_v2.db scan \
  '192.0.2.10' --profile deep_identification --tcp-ports 1-65535 \
  --probes http,rtsp --active-consent --authorized

# Отдельно выбранные UDP-пробы на произвольном порту.
.venv/bin/python -m ip2domain.scanning.cli --db ./scanner_v2.db scan \
  '192.0.2.10' --profile deep_identification --tcp-ports '' \
  --udp-ports 45678 --probes snmp,dns,coap \
  --active-consent --authorized

.venv/bin/python -m ip2domain.scanning.cli --db ./scanner_v2.db status SCAN_ID
.venv/bin/python -m ip2domain.scanning.cli --db ./scanner_v2.db resume SCAN_ID --authorized
.venv/bin/python -m ip2domain.scanning.cli --db ./scanner_v2.db export SCAN_ID
```

`192.0.2.10` — пример, замените разрешённым адресом стенда.
Широкий диапазон имеет существенную стоимость; используйте исключения и лимиты.
Параллельность CLI и API ограничена executor-lease в одной inventory-БД.
Разные БД не имеют общего лимита, распределённых агентов пока нет.

### Дополнительные разрешения

* `industrial_consent` / `--industrial-consent`: OPC UA и Modbus только
  внутри активного профиля. `modbus_unit_id` задаётся явно, по умолчанию 1.
  Broadcast unit ID запрещён; перебора всех unit ID нет.
* `web_enrichment` / `--web-enrichment`: WebDAV, WebSocket, ограниченное
  чтение HTTP-ресурсов. `resource_paths` — до 8 origin-relative путей,
  в CLI повторяемый `--resource-path`.
* `nmap`: дополнительный TCP service detection установленным Nmap,
  без NSE. Его полный набор version probes имеет собственные риски;
  `industrial_consent` ограничивает нативные промышленные кодеки,
  **не фильтрует внутреннюю базу Nmap**.

Нативные пробы не отправляют активные payload на 9100–9102.
Для Nmap отдельный API-параметр `nmap_all_ports` снимает исключение при
`nmap=true`; не включайте его без понимания риска печати данных.

## Реальное покрытие протоколов

`GET /api/scanner/v2/capabilities` формируется из того же реестра, который
используется при выполнении. Подсказки портов влияют только на порядок проб.
`enabled_probes=None` — набор по умолчанию; `[]` — без выбранных активных проб.
Баннеры и уже установленное TCP-соединение — отдельные этапы.

| Детектор | Транспорт | Глубина |
|---|---|---|
| SSH, FTP, SMTP, IMAP, POP3, Telnet | TCP | Начальная сигнатура, без входа |
| TLS | TCP | Handshake, версия/cipher; доверие сертификату не проверяется |
| HTTP/HTTPS | TCP/TLS | HEAD `/`, статус, ограниченные заголовки |
| RTSP/RTSPS | TCP/TLS | OPTIONS, корреляция CSeq, состояние авторизации |
| MQTT/MQTTS | TCP/TLS | CONNECT/CONNACK без credentials, публикаций и подписок |
| SIP/SIPS | TCP/TLS; SIP/UDP | OPTIONS, Call-ID/CSeq, без звонка |
| DNS/DoT | TCP/TLS; DNS/UDP | Root SOA, без recursion, корреляция вопроса |
| CoAP | UDP | Empty ping/RST, без чтения ресурса |
| NTP | UDP | Time request/response, origin timestamp |
| SNMP | UDP | SNMPv3 engine discovery/Report, без community guesses и чтения OID |
| rpcbind, NFS | TCP/UDP | RPC NULL, без mount, listing и файлов; NFS v3 |
| OPC UA | TCP | Hello/Acknowledge, без session и чтения nodes |
| Modbus TCP | TCP | Read Device Identification 43/14, без process registers |

Первый подтверждённый прикладной протокол прекращает нерелевантные пробы:
сканер не отправляет бинарные команды уже распознанному HTTP-приложению.
Это не гарантирует обнаружение всех мультиплексируемых протоколов.
Общий endpoint budget может закончиться раньше всех детекторов:
неисполненные проверки отмечаются `skipped_budget`.

### HTTP enrichment

После подтверждения HTTP/HTTPS, только при отдельном разрешении:

* WebDAV: OPTIONS и DAV compliance header, без PROPFIND/PUT.
* WebSocket: проверка Upgrade и вычисленного Sec-WebSocket-Accept.
  Без прикладных сообщений, подпротоколов и вызовов управления.
* HLS: сигнатура playlist, не загрузка сегментов.
* MJPEG: multipart boundary и JPEG marker.
* MPEG-TS: синхронизация пакетов в ограниченном образце.
* HTTP snapshot: JPEG marker.

Максимум 8192 байта тела на запрос, без декомпрессии и follow redirects.
Подтверждение сигнатуры **не равно** декодированию/проигрыванию видео:
`verified_media=false`.
Статус 401 без разрешённых credentials сохраняется, а не обходится.
Пути/URL из ответа не становятся новыми целями автоматически.

### Что пока НЕ реализовано в новом контуре

Нативные RTMP, RTP/RTCP, WebRTC, SRT, TR-069, EtherNet/IP, DNP3,
BACnet/IP, SMB, KNX/IP, DLMS/COSEM, IPP/LPD/JetDirect, RDP/ICA,
MAVLink, OCPP, DICOM/HL7; multicast/passive collectors; distributed agents.
Nmap может распознать некоторые из них по установленной базе сигнатур,
но это не равнозначно собственному тестированному адаптеру.
Существующие реализации камерных RTMP/HLS/WebRTC и других протоколов
остаются в старом профиле, не удалены и не объявлены новыми детекторами.

## Хранение и возобновление

Новые задания используют `execution_mode=staged`. Выполнение разделено:

```text
discovery blocks → identify queue → optional enrich queue
```

* Discovery делает TCP connect и читает ограниченный начальный баннер.
  Оно не ждёт завершения прикладных проб всех предыдущих endpoints.
* UDP передаётся в identification без пустых датаграмм и без утверждения,
  что порт открыт. Фактические UDP-проверки выполняются детекторами.
* Запись endpoint, помещение в очередь identification и checkpoint порта
  выполняются одной SQLite-транзакцией. Нет окна потери между этими записями.
* Завершение identification и передача enrichment также атомарны.
* Статус `completed` выставляется только после завершения sweep и всех
  следующих очередей. Завершённый sweep сам по себе не завершает задание.
* `queue_capacity` ограничивает сумму queued/leased endpoint-задач.
  При переполнении discovery ждёт, не отбрасывая найденные порты.
  Дополнительно каждый discovery worker может удерживать один ещё не
  переданный endpoint. Завершённые записи остаются в БД для resume/диагностики:
  лимит очереди не является лимитом общего размера БД.
* Identification не повторяет discovery connect после получения endpoint.
  Протокольные пробы при необходимости открывают собственные соединения.
* Enrichment имеет независимый пул. Пауза во время enrichment не требует
  повторного sweep/identification после resume.

Параметры API/CLI:

| Параметр | По умолчанию | Смысл |
|---|---|---|
| `workers` / `--workers` | 8 | Пул identification и общий лимит сетевых endpoint-операций |
| `discovery_workers` / `--discovery-workers` | 4 | Пул discovery |
| `enrichment_workers` / `--enrichment-workers` | 2 | Пул enrichment |
| `queue_capacity` / `--queue-capacity` | 1024 | Максимум незавершённых queued/leased задач следующих этапов |

Rate limit, лимиты на хост/подсеть и общий сетевой лимит разделяются между
всеми тремя пулами. Поэтому очень медленный сервис всё ещё может задержать
операции на том же хосте из-за `per_host`; это намеренное ограничение нагрузки.
Nmap по-прежнему имеет собственные внутренние запросы и rate budget.

API задания содержит `stages.discover`, `stages.identify`, `stages.enrich`:
очереди, число завершённых задач и отдельные счётчики проверок.
Глобальный `coverage.tested` не считает один endpoint дважды: отрицательные
TCP-результаты учитываются в discovery, открытые TCP и UDP — в identification.
Enrichment не увеличивает число проверенных портов.

Старые сохранённые задания **без `execution_mode`** возобновляются прежним
последовательным исполнителем; явный `execution_mode=sequential` тоже доступен.
Нельзя менять режим существующего задания вручную в БД: смысл checkpoint
у исполнителей различается. Старый `/api/v2` не переключается на новый pipeline.

* Адреса/порты генерируются блоками, не полным произведением.
* Worker имеет fenced token; просроченный владелец не может записать результат.
* В БД один живой executor lease: второй процесс не захватывает текущую задачу.
* Завершённые порты имеют checkpoint внутри блока.
* Успешная проба сохраняется до окончания endpoint и блока.
* При повторе порта ранее подтверждённые сервисы не стираются пустым результатом.
* При принудительном убийстве процесса нужно дождаться истечения lease
  (до 60 секунд); обычная отмена освобождает его.
* Ошибка/пауза не равны отмене; отменённое завершённое задание не возобновляется.

По умолчанию отдельные строки сохраняются для открытых endpoint и сервисов.
Остальные состояния — компактные счётчики покрытия по блокам.
`retain_all_states=true` сохраняет отдельный документ каждого порта.
В staged-режиме `coverage` объединяет завершённые discovery-блоки и задачи
identification; `in_progress_coverage` относится к текущим discovery-блокам.
Отдельные счётчики enrichment находятся в `stages.enrich.coverage`.
В sequential-режиме сохраняется прежняя семантика покрытия по блокам.

`first_seen`/`last_seen` пока внутри задания, не сквозная история устройства.
Таблица камер не используется для хранения сетевых сервисов.
API не выполняет автоматическое возобновление после рестарта: нужно явное
действие администратора.

## Разбиение модулей

* `scope.py`, `policies.py` — область и разрешения;
* `pipeline.py` — совместимый фасад выбора исполнителя;
* `staged_pipeline.py`, `stage_workers.py`, `stages.py` — три независимых этапа;
* `stage_queue.py`, `endpoint_store.py`, `leases.py` — атомарные handoff,
  общая запись результатов и управление отменой/lease;
* `sequential.py` — совместимость со старыми checkpoints;
* `checkpoints.py`, `persistence.py` — leases, fenced commits и хранение;
* `detection/wire.py`, `catalog.py`, `scheduler.py` — контракты и запуск кодеков;
* `discovery/tcp.py`, `udp.py` — транспортные этапы;
* `protocols/*.py` — небольшие независимые wire-кодеки;
* `transports/*.py` — ограниченные сетевые операции;
* `enrichment/web.py` — обработка HTTP-ресурсов;
* `classification.py` — правила классификации по явным продуктовым сведениям;
* `web/routers/inventory_scanner.py` — новый API без изменений камерного контракта.

Общий `ProbeRegistry`/`ProbeRunner` прежнего рефакторинга сохраняется для
камерных адаптеров. `WireRegistry` — более узкий контракт packet/parser,
а не второй планировщик заданий.

## Проверки и оставшиеся инженерные ограничения

```bash
IP2DOMAIN_DB_PATH=/tmp/ip2domain-scanner-tests.db .venv/bin/python -m pytest -q
```

Тесты включают случайные loopback-порты для HTTP/RTSP/WebSocket,
корреляцию бинарных ответов, таймауты UDP, внешнюю отмену, replay/checkpoints,
executor fencing, запрет промышленных проб без согласия, отказ от redirects,
совместимость старого API и временные SQLite.
Это тесты fixtures/локальных серверов, **не сертификация на реальном PLC,
медицинском оборудовании или всех моделях NFS/SNMP-устройств**.

Следующие приоритеты:

1. Ввести нормализованные сервисы/ресурсы и историю по нескольким заданиям.
2. Перевести camera enrichment на общий endpoint/scope/credential контракт.
3. Добавлять специализированные протоколы по одному с межоперабельными
   тестами и отдельной политикой риска.
4. Добавить распределённые агенты, TLS-аутентификацию агентов и глобальные лимиты.
