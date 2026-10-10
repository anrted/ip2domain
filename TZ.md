# MASTER PROMPT

## Разработка универсального многостадийного Network Device / Service / Endpoint Scanner

Мне необходимо разработать полноценную систему сетевой инвентаризации и fingerprinting.

Это НЕ должен быть просто port scanner.

Главная задача системы — по списку IP-адресов максимально полно определить:

* какие TCP/UDP порты доступны;
* какие реальные сервисы работают на этих портах;
* какие протоколы используются;
* какой software/product/server/device находится за сервисом;
* производитель;
* модель;
* версия;
* firmware;
* какие endpoints доступны;
* какие media streams существуют;
* какие логические устройства находятся за одним IP;
* какие authentication mechanisms используются;
* какие credentials из явно предоставленного пользователем списка подходят;
* какие сервисы относятся к одному физическому/логическому устройству;
* на основании каких конкретных признаков был сделан каждый вывод.

Главный принцип:

> **Port → Service → Protocol → Product → Vendor → Model → Endpoint → Device → Stream → Correlation**

А не:

> IP → Port → Guess.

---

# 1. ОСНОВНОЙ PIPELINE

Система должна работать как многостадийный pipeline:

```text
TARGETS
    ↓
HOST DISCOVERY
    ↓
PORT DISCOVERY
    ↓
SERVICE DETECTION
    ↓
PROTOCOL IDENTIFICATION
    ↓
SERVICE-SPECIFIC ENUMERATION
    ↓
PRODUCT / VENDOR FINGERPRINTING
    ↓
MODEL / VERSION / FIRMWARE DETECTION
    ↓
ENDPOINT DISCOVERY
    ↓
AUTHENTICATION DETECTION
    ↓
SUPPLIED CREDENTIAL CHECK
    ↓
MEDIA / CHANNEL / DEVICE ENUMERATION
    ↓
CROSS-SERVICE CORRELATION
    ↓
FINAL DEVICE INVENTORY
```

Каждая стадия должна сохранять свои результаты.

Нельзя терять исходные данные после последующего fingerprinting.

---

# 2. КЛЮЧЕВАЯ МОДЕЛЬ ДАННЫХ

Система должна мыслить следующей иерархией:

```text
Host
 ├── Port
 │    └── Service
 │          └── Protocol
 │                └── Product
 │                      └── Endpoint
 │                            └── Device
 │                                  └── Stream / Channel
```

Но необходимо учитывать, что реальная структура может быть сложнее:

```text
IP
 ├── HTTP
 ├── HTTPS
 ├── RTSP
 ├── ONVIF
 └── proprietary SDK
        ↓
      NVR
        ├── Camera 1
        │    ├── Main stream
        │    └── Sub stream
        │
        ├── Camera 2
        │    ├── Main stream
        │    └── Sub stream
        │
        └── Camera N
```

Поэтому:

> **Один IP ≠ одно устройство.**

Также:

> **Один порт ≠ один сервис.**

И:

> **Один RTSP endpoint ≠ одна камера.**

---

# 3. TARGET INPUT

Поддержать:

* одиночный IPv4;
* CIDR;
* диапазон IP;
* несколько целей;
* список целей;
* исключения.

Пример:

```text
192.168.1.10
192.168.1.20-192.168.1.50
192.168.2.0/24
```

Поддержать:

* target groups;
* Network ID;
* site ID;
* scan tags;
* comments.

---

# 4. HOST DISCOVERY

До полноценного port scan при необходимости использовать:

* ICMP;
* ARP;
* TCP SYN/Connect discovery;
* UDP discovery;
* DNS;
* reverse DNS;
* mDNS;
* SSDP;
* WS-Discovery;
* LLDP;
* CDP.

Важно:

Host может быть alive даже если:

* ICMP заблокирован;
* TCP стандартные порты закрыты;
* UDP не отвечает.

Поэтому использовать несколько механизмов discovery.

---

# 5. PORT DISCOVERY

Поддержать:

### TCP

* Top 10;
* Top 100;
* Top 1000;
* пользовательский список;
* диапазоны;
* 1–65535.

### UDP

Поддержать:

* пользовательский список;
* профильные UDP ports;
* protocol-driven UDP discovery.

Система не должна считать:

```text
554 → RTSP
8554 → RTSP
80 → HTTP
5060 → SIP
502 → Modbus
```

только на основании номера порта.

Порт является только **hint**.

Сервис необходимо подтвердить protocol probe.

---

# 6. SERVICE DETECTION

Для каждого открытого порта использовать:

* banner grabbing;
* protocol handshake;
* service probes;
* TLS handshake;
* HTTP response;
* protocol-specific probes;
* server headers;
* certificates;
* ALPN;
* SNI;
* timing;
* response structure.

Поддержать архитектуру, аналогичную концепции `service probes` Nmap: probe → response → matcher → service/product/version.

Но не копировать архитектуру Nmap буквально — сделать собственный extensible engine.

---

# 7. UNKNOWN SERVICES

Если сервис неизвестен:

НЕ писать просто:

```text
Unknown
```

Сохранять:

```text
port
transport
banner
raw response fingerprint
TLS fingerprint
protocol characteristics
timing
response length
probable protocol
probable product
```

После этого запускать:

```text
Generic Fingerprint Engine
```

Неизвестные fingerprints должны иметь возможность сохраняться в базу для последующего распознавания.

---

# 8. SERVICE PLUGIN ARCHITECTURE

Каждый protocol/service module должен иметь единый интерфейс:

```text
detect()
fingerprint()
enumerate()
discover_endpoints()
detect_auth()
authenticate()
enrich()
correlate()
```

Например:

```text
plugins/
├── rtsp/
├── http/
├── onvif/
├── sip/
├── snmp/
├── mqtt/
├── modbus/
├── opcua/
├── bacnet/
├── smb/
├── printer/
├── router/
├── industrial/
└── ...
```

Core scanner не должен знать детали конкретного протокола.

---

# 9. VIDEO / RTSP

RTSP должен быть одним из наиболее развитых модулей.

Поддержать:

* RTSP;
* RTSPS;
* RTP;
* RTCP;
* RTSP over TCP;
* RTP over UDP;
* interleaved RTP;
* authentication;
* SDP;
* media tracks;
* codec identification.

После обнаружения RTSP:

```text
RTSP
 ↓
OPTIONS
 ↓
Server fingerprint
 ↓
Authentication detection
 ↓
Vendor detection
 ↓
Model detection
 ↓
Endpoint generation
 ↓
Endpoint enumeration
 ↓
SDP parsing
 ↓
Stream discovery
 ↓
Channel correlation
```

---

# 10. RTSP ENDPOINT ENGINE

Это критически важная часть проекта.

Не ограничиваться несколькими стандартными URI.

Создать отдельный:

```text
RTSP Endpoint Corpus
```

и:

```text
RTSP Endpoint Generator
```

Corpus должен содержать **1000+ endpoint patterns/candidates** и постоянно расширяться.

Но не делать просто гигантский hardcoded список.

Использовать шаблоны:

```text
/vendor
/product
/model
/channel
/stream
/profile
/subtype
/codec
/firmware
```

Например:

```text
/Streaming/Channels/{channel}{stream}
/cam/realmonitor?channel={channel}&subtype={stream}
/h264Preview_{channel:02d}_{stream}
/live/{channel}/{stream}
/stream{channel}
/video{channel}
/profile{channel}
/ch{channel}/{stream}
```

Генератор должен учитывать:

* vendor;
* product family;
* model;
* firmware;
* number of channels;
* main/sub stream;
* profile;
* channel numbering;
* stream numbering.

---

# 11. RTSP VENDOR PROFILES

Создать отдельные profiles минимум для:

* Hikvision;
* Dahua;
* Axis;
* Hanwha;
* Uniview;
* Bosch;
* Sony;
* Panasonic;
* Vivotek;
* Reolink;
* Amcrest;
* Foscam;
* HiWatch;
* TVT;
* Provision;
* Milesight;
* Grandstream;
* generic cameras;
* generic NVR;
* generic DVR.

Каждый profile должен содержать:

```yaml
vendor:
product_family:
models:
firmware_patterns:
ports:
rtsp_patterns:
http_patterns:
onvif_patterns:
authentication:
fingerprints:
channel_patterns:
stream_patterns:
```

---

# 12. MULTI-CAMERA / NVR LOGIC

Это обязательная возможность.

Один IP может быть:

```text
NVR
DVR
VMS
media gateway
video server
```

и предоставлять множество камер.

Например:

```text
192.168.1.50

Channel 1
  Main
  Sub

Channel 2
  Main
  Sub

Channel 3
  Main
  Sub

...

Channel 16
  Main
  Sub
```

Scanner должен обнаруживать каждый stream как отдельный объект.

Пример:

```json
{
  "host": "192.168.1.50",
  "device": "NVR",
  "channels": [
    {
      "channel": 1,
      "streams": [
        {
          "profile": "main",
          "uri": "...",
          "codec": "H264"
        },
        {
          "profile": "sub",
          "uri": "...",
          "codec": "H264"
        }
      ]
    }
  ]
}
```

Не ограничиваться количеством streams, найденных через один endpoint.

Использовать:

* RTSP;
* ONVIF;
* HTTP API;
* vendor fingerprint;
* channel patterns;
* model capabilities

для определения максимально вероятного количества каналов.

---

# 13. ONVIF

ONVIF должен быть отдельным полноценным subsystem.

Поддержать:

* WS-Discovery;
* Device Management;
* Media;
* Media2;
* PTZ;
* Events;
* Imaging;
* Analytics;
* Recording;
* Replay;
* Receiver;
* DeviceIO;
* Access Control;
* Door Control;
* Thermal;
* WebRTC;
* другие доступные сервисы согласно capabilities.

ONVIF официально определяет отдельные network interface specifications и service definitions, поэтому нельзя сводить ONVIF только к «поиску камеры».

Discovery должен учитывать WS-Discovery и UDP 3702, но также учитывать, что устройство может быть non-discoverable.

После discovery:

```text
WS-Discovery
 ↓
Device XAddr
 ↓
GetDeviceInformation
 ↓
Capabilities
 ↓
Media / Media2
 ↓
Profiles
 ↓
Stream URI
 ↓
PTZ / Events / Imaging / Analytics
```

Важно:

ONVIF API содержит как read-only, так и state-changing операции.

По умолчанию разрешены только безопасные read-only методы.

Не выполнять:

* SetNetwork...
* SetHostname
* SetDNS
* SetUsers
* CreateUsers
* DeleteUsers
* SystemReboot
* FactoryReset
* PTZ movement
* configuration changes.

---

# 14. HTTP / HTTPS

Глубокий HTTP fingerprinting:

* status code;
* headers;
* Server;
* title;
* favicon;
* cookies;
* redirects;
* TLS;
* certificate;
* ALPN;
* HTTP version;
* framework;
* JavaScript;
* WebSocket;
* WebDAV.

Безопасно проверять стандартные endpoints:

```text
/
 /login
 /admin
 /api
 /api/v1
 /api/v2
 /api/docs
 /swagger
 /swagger.json
 /openapi.json
 /health
 /status
 /info
```

Для известных vendor profiles использовать дополнительные read-only endpoints.

---

# 15. MEDIA PROTOCOLS

Поддержать:

```text
RTSP
RTSPS
RTP
RTCP
RTMP
RTMPS
HLS
MPEG-TS
HTTP-FLV
MJPEG
WebRTC
SRT
```

Для каждого:

* detect;
* fingerprint;
* server identification;
* authentication;
* endpoint discovery;
* stream discovery;
* codec discovery;
* metadata extraction.

---

# 16. VIDEO MANAGEMENT SYSTEMS

Поддерживать fingerprints для:

* Flussonic;
* Milestone;
* ZoneMinder;
* Frigate;
* Shinobi;
* Blue Iris;
* Wowza;
* Nimble Streamer;
* generic media servers.

Идентифицировать:

* server;
* version;
* media protocols;
* stream endpoints;
* APIs;
* authentication.

---

# 17. IPTV

Поддерживать:

* UDP multicast;
* RTP;
* RTSP;
* RTMP;
* HLS;
* MPEG-TS;
* SRT;
* HTTP-FLV.

Обнаруживать:

* M3U;
* M3U8;
* playlists;
* channels;
* stream metadata;
* codec;
* transport.

Не ограничиваться TCP scanning — IPTV часто использует UDP/multicast.

---

# 18. VOIP / SIP

Поддерживать:

* SIP;
* SIP-TLS;
* RTP;
* RTCP;
* IAX2.

Определять:

* phone;
* PBX;
* registrar;
* proxy;
* SBC;
* SIP gateway;
* intercom;
* recording system.

Использовать:

* OPTIONS;
* User-Agent;
* Server;
* Allow;
* Supported;
* authentication challenge.

Не выполнять вызовы.

---

# 19. AUDIO

Обнаруживать:

* IP microphones;
* IP speakers;
* paging systems;
* audio encoders;
* audio decoders;
* intercoms.

Поддерживать:

* SIP;
* RTP;
* RTSP;
* HTTP/HTTPS.

Определять:

* vendor;
* model;
* codec;
* streams;
* authentication.

---

# 20. CALL RECORDING

Обнаруживать:

* call recording servers;
* SIP recording systems;
* SPRecord-like systems;
* VoIP recorders.

Проверять:

* SIP;
* RTP;
* HTTP;
* HTTPS;
* proprietary TCP.

Не скачивать содержимое разговоров.

Определять только:

* vendor;
* product;
* version;
* service;
* recording interfaces;
* authentication.

---

# 21. ACCESS CONTROL

Поддерживать:

* door controllers;
* card readers;
* biometric terminals;
* access gateways.

Протоколы:

```text
HTTP
HTTPS
TCP
UDP
SNMP
MQTT
Modbus TCP
proprietary
```

Read-only:

* vendor;
* model;
* firmware;
* number of doors;
* controller capabilities.

Никаких:

* unlock;
* relay activation;
* credential modification.

---

# 22. INTERCOM

Поддерживать:

* SIP;
* RTSP;
* HTTP;
* HTTPS;
* ONVIF;
* RTP.

Коррелировать:

```text
Camera
+
Microphone
+
Speaker
+
SIP
+
Door controller
```

в одно логическое устройство.

---

# 23. ANPR / LPR

Поддерживать:

* HTTP;
* HTTPS;
* RTSP;
* ONVIF;
* proprietary APIs.

Определять:

* ANPR camera;
* recognition engine;
* vendor;
* model;
* firmware;
* streams;
* metadata APIs.

Не извлекать реальные номера автомобилей без специального разрешения.

---

# 24. TRAFFIC SYSTEMS

Обнаруживать:

* traffic cameras;
* speed cameras;
* traffic sensors;
* vehicle counters;
* traffic controllers;
* variable message systems.

Протоколы:

```text
RTSP
HTTP
HTTPS
SNMP
TCP
UDP
Modbus
proprietary
```

Только inventory.

Не отправлять управляющие команды.

---

# 25. PARKING

Обнаруживать:

* parking cameras;
* ANPR;
* barriers;
* ticket machines;
* payment terminals;
* parking controllers;
* management servers.

Коррелировать:

```text
Camera
+
ANPR
+
Barrier
+
Controller
+
Server
```

---

# 26. IoT

Поддерживать:

* MQTT;
* CoAP;
* HTTP;
* HTTPS;
* Modbus TCP;
* SNMP;
* WebSocket;
* mDNS;
* SSDP.

Обнаруживать:

* sensors;
* gateways;
* hubs;
* controllers.

---

# 27. INDUSTRIAL / OT

Поддерживать:

* Modbus TCP;
* OPC UA;
* EtherNet/IP;
* PROFINET;
* Siemens S7;
* DNP3;
* IEC 60870-5-104;
* BACnet/IP;
* MQTT;
* proprietary industrial protocols.

Только read-only discovery.

Определять:

* PLC;
* RTU;
* gateway;
* controller;
* industrial server;
* engineering station.

Никаких:

* writes;
* coils;
* register modifications;
* program upload;
* reboot;
* configuration changes.

---

# 28. SCADA

Обнаруживать:

* SCADA;
* historian;
* OPC server;
* engineering station;
* industrial gateway.

Определять:

* vendor;
* product;
* version;
* server role;
* protocol;
* security mode.

---

# 29. BMS

Поддерживать:

* BACnet/IP;
* Modbus TCP;
* KNX/IP;
* MQTT;
* HTTP;
* HTTPS;
* SNMP.

Обнаруживать:

* HVAC;
* lighting;
* building controllers;
* automation gateways.

Только read-only.

---

# 30. FIRE SAFETY

Обнаруживать:

* fire alarm panels;
* fire gateways;
* monitoring systems.

Поддерживать:

* TCP/IP;
* HTTP;
* HTTPS;
* SNMP;
* Modbus;
* proprietary.

Не выполнять:

* alarm;
* reset;
* acknowledge;
* disable;
* configuration.

---

# 31. ELEVATORS

Обнаруживать:

* elevator controllers;
* dispatch systems;
* monitoring gateways.

Определять:

* vendor;
* model;
* firmware;
* protocol.

Только passive/read-only identification.

---

# 32. UPS / POWER

Поддерживать:

* SNMP;
* HTTP;
* HTTPS;
* Modbus TCP.

Обнаруживать:

* UPS;
* PDU;
* power controllers;
* battery monitoring.

Не выполнять shutdown/reboot.

---

# 33. METERS

Поддерживать:

* Modbus;
* DLMS/COSEM;
* MQTT;
* HTTP;
* proprietary.

Обнаруживать:

* electricity;
* gas;
* water;
* energy gateways.

---

# 34. PRINTERS / MFP

Поддерживать:

* IPP;
* LPD;
* JetDirect;
* SNMP;
* HTTP;
* HTTPS;
* SMB;
* FTP.

Определять:

* vendor;
* model;
* firmware;
* printer name;
* capabilities.

---

# 35. STORAGE / NAS

Поддерживать:

* SMB;
* NFS;
* FTP;
* SFTP;
* HTTP;
* HTTPS;
* WebDAV;
* iSCSI.

Определять:

* NAS vendor;
* model;
* OS;
* firmware;
* available services.

Не читать пользовательские файлы.

---

# 36. NETWORK INFRASTRUCTURE

Поддерживать:

### Routers

```text
HTTP
HTTPS
SSH
Telnet
SNMP
TR-069
UPnP
DNS
DHCP
```

### Switches

```text
SNMP
SSH
Telnet
HTTP
HTTPS
LLDP
CDP
```

### Firewalls

```text
HTTPS
SSH
SNMP
IPsec/IKE
SSL VPN
```

### Wi-Fi AP

```text
HTTP
HTTPS
SSH
SNMP
CAPWAP
LLDP
```

### Wireless bridges

```text
HTTP
HTTPS
SSH
SNMP
```

Определять:

* vendor;
* model;
* firmware;
* device role;
* management interfaces.

---

# 37. KVM / THIN CLIENTS

Поддерживать:

* HTTP;
* HTTPS;
* SSH;
* RDP;
* ICA/HDX;
* proprietary protocols.

Определять:

* KVM;
* console server;
* thin client;
* RDP gateway.

---

# 38. 3D PRINTERS

Поддерживать:

* HTTP;
* HTTPS;
* WebSocket;
* MQTT;
* OctoPrint;
* Klipper/Moonraker;
* vendor APIs.

Определять:

* vendor;
* model;
* firmware;
* print server.

Не запускать печать.

---

# 39. ROBOTS

Поддерживать:

* TCP/IP;
* OPC UA;
* EtherNet/IP;
* PROFINET;
* HTTP;
* HTTPS;
* proprietary.

Только identification.

---

# 40. DRONES / MAVLINK

Поддерживать:

* UDP;
* TCP;
* MAVLink;
* HTTP/HTTPS.

Определять:

* ground station;
* telemetry endpoint;
* protocol;
* vendor.

Не отправлять flight-control commands.

---

# 41. RADIO / PTT

Поддерживать:

* SIP;
* RTP;
* HTTP;
* HTTPS;
* proprietary.

Обнаруживать:

* PTT;
* dispatch;
* radio gateway;
* recording server.

---

# 42. SATELLITE

Поддерживать:

* HTTP;
* HTTPS;
* SNMP;
* SSH;
* proprietary.

Определять:

* modem;
* terminal;
* vendor;
* model;
* firmware.

---

# 43. TELEMATICS / GPS

Поддерживать:

* TCP;
* UDP;
* MQTT;
* HTTP;
* HTTPS;
* proprietary.

Определять:

* tracker;
* gateway;
* protocol;
* vendor;
* model.

Не получать location history.

---

# 44. FUEL STATIONS

Обнаруживать:

* dispenser controllers;
* tank systems;
* station gateways.

Поддерживать:

* TCP/IP;
* Modbus;
* HTTP;
* HTTPS;
* proprietary.

Только inventory.

---

# 45. ATM / PAYMENT

Обнаруживать:

* ATM;
* payment terminal;
* kiosk;
* fiscal terminal.

Проверять только технические признаки.

Не извлекать:

* card data;
* PIN;
* transaction data;
* financial information.

---

# 46. HOTEL SYSTEMS

Обнаруживать:

* locks;
* room controllers;
* gateways;
* hotel terminals.

Только read-only.

Никаких:

* unlock;
* credential modification;
* room control.

---

# 47. SMART HOME

Поддерживать:

* MQTT;
* HTTP;
* HTTPS;
* WebSocket;
* CoAP;
* mDNS;
* SSDP;
* Zigbee/IP gateways.

Обнаруживать:

* hubs;
* controllers;
* IoT gateways.

---

# 48. SOLAR / ENERGY

Поддерживать:

* Modbus TCP;
* HTTP;
* HTTPS;
* MQTT;
* SNMP.

Определять:

* inverter;
* battery controller;
* energy gateway;
* vendor;
* model;
* firmware.

Только read-only telemetry.

---

# 49. EV CHARGERS

Поддерживать:

* OCPP;
* HTTP;
* HTTPS;
* WebSocket;
* MQTT;
* Modbus TCP.

Определять:

* vendor;
* model;
* firmware;
* OCPP version;
* connector count;
* capabilities.

Не запускать/останавливать зарядку.

---

# 50. LABORATORY EQUIPMENT

Поддерживать:

* TCP/IP;
* HTTP;
* HTTPS;
* Modbus;
* OPC UA;
* proprietary.

Определять:

* vendor;
* model;
* firmware;
* device type.

---

# 51. MEDICAL

Поддерживать:

* DICOM;
* HL7;
* HTTP;
* HTTPS;
* TCP/IP;
* proprietary.

DICOM:

```text
C-ECHO
AE Title
Implementation Class UID
Implementation Version
Supported services
Modality
```

Только безопасная capability discovery.

Не загружать медицинские изображения и PHI.

---

# 52. AUTHENTICATION ENGINE

Отдельный общий модуль.

Определять:

```text
None
Basic
Digest
Bearer
JWT
Cookie/session
API key
Client certificate
SIP auth
RTSP auth
proprietary
```

Пользователь может загрузить credential list:

```text
username/password
username/password
username/password
```

Разрешается проверять только явно переданные credentials.

При успешной авторизации:

```text
AUTHENTICATED
 ↓
create session
 ↓
read-only enumeration
```

Не делать:

* brute force;
* password spraying;
* unlimited guessing.

---

# 53. DEVICE FINGERPRINT ENGINE

Использовать корреляцию:

```text
Ports
+
Banners
+
Services
+
Protocols
+
HTTP
+
TLS
+
RTSP
+
ONVIF
+
SNMP
+
SIP
+
MAC/OUI
+
Endpoints
+
Firmware strings
```

Пример:

```text
Hikvision NVR
Confidence: 97.4%

Evidence:
✓ HTTP fingerprint
✓ RTSP Server
✓ ONVIF Manufacturer
✓ proprietary SDK port
✓ endpoint structure
✓ firmware signature
```

---

# 54. CONFIDENCE SYSTEM

Каждое определение должно иметь confidence:

```text
0–30%   weak
30–60%  possible
60–80%  probable
80–95%  high
95–100% confirmed
```

Необходимо показывать evidence.

---

# 55. ENDPOINT ENGINE

Endpoint discovery должен использовать:

```text
generic corpus
vendor corpus
product corpus
model corpus
firmware corpus
protocol-derived candidates
```

Каждый endpoint:

```json
{
  "uri": "...",
  "protocol": "rtsp",
  "source": "vendor-profile",
  "confidence": 0.91,
  "status": "discovered",
  "authentication": "digest"
}
```

---

# 56. CORRELATION ENGINE

Система должна объединять сервисы.

Например:

```text
80 HTTP
443 HTTPS
554 RTSP
3702 ONVIF
8000 proprietary
```

→

```text
Hikvision NVR
```

а не пять независимых объектов.

---

# 57. DATABASE

Предусмотреть отдельные сущности:

```text
ScanJob
Target
Host
Port
Service
Protocol
Product
Vendor
Model
Firmware
Device
Endpoint
Credential
Authentication
Stream
Channel
Fingerprint
Evidence
ScanEvent
```

---

# 58. FINGERPRINT DATABASE

Структура:

```text
fingerprints/
├── vendors/
├── products/
├── models/
├── firmware/
├── protocols/
├── services/
└── endpoints/
```

Каждый fingerprint должен быть versioned.

---

# 59. SELF-LEARNING FINGERPRINTS

Если найден неизвестный сервис:

```text
Unknown
 ↓
capture fingerprint
 ↓
manual classification
 ↓
save signature
 ↓
future detection
```

Должна существовать возможность добавлять fingerprint без изменения scanner core.

---

# 60. SCAN MODES

Реализовать:

### FAST

```text
Host discovery
TCP Top Ports
Basic service detection
```

### STANDARD

```text
TCP Top 1000
Service detection
Basic protocol detection
```

### FULL

```text
TCP 1–65535
UDP profiles
Service detection
Protocol detection
Fingerprinting
```

### DEEP

```text
Full ports
Full protocol enumeration
Vendor/model detection
Endpoint discovery
Supplied credentials
Device correlation
```

### VIDEO

```text
RTSP
RTSPS
ONVIF
RTP
RTCP
HLS
RTMP
WebRTC
MJPEG
SRT
NVR/VMS profiles
```

### VOIP

```text
SIP
RTP
RTCP
IAX
PBX
IP phones
intercom
recording
```

### OT SAFE

```text
Modbus
OPC UA
BACnet
DNP3
S7
EtherNet/IP
IEC 60870
```

только read-only.

---

# 61. PERFORMANCE

Использовать отдельные worker pools:

```text
Port Workers
      ↓
Service Workers
      ↓
Protocol Workers
      ↓
Endpoint Workers
      ↓
Enrichment Workers
```

Настройки:

* discovery workers;
* service workers;
* protocol workers;
* enrichment workers;
* global rate;
* per-host rate;
* per-protocol rate;
* timeout;
* retry;
* queue size;
* max connections.

---

# 62. BACKPRESSURE

Если один IP является огромным NVR/VMS:

```text
IP
 ↓
10,000 endpoint candidates
```

он не должен заблокировать весь scan.

Использовать:

* queue;
* priority;
* concurrency limits;
* per-host limits;
* endpoint budget;
* protocol budget.

---

# 63. ENDPOINT BUDGET

Для каждого protocol module предусмотреть:

```text
max_candidates
max_requests_per_host
max_parallel_requests
timeout
```

Например:

```text
RTSP:
  max candidates = configurable
  concurrency = configurable
```

Это необходимо, чтобы огромная база endpoint templates не превращалась в бесконтрольный запросный storm.

---

# 64. SAFETY MODEL

По умолчанию:

```text
SAFE READ-ONLY
```

Запрещены без отдельного explicit opt-in:

* configuration changes;
* reboot;
* factory reset;
* PTZ movement;
* door unlock;
* barrier opening;
* relay activation;
* Modbus writes;
* PLC writes;
* MQTT publish;
* printer jobs;
* EV charge start/stop;
* robot commands;
* drone control;
* alarm triggering;
* firewall changes;
* user creation/deletion.

---

# 65. RAW EVIDENCE

Для каждого результата сохранять evidence.

Например:

```json
{
  "type": "http_header",
  "header": "Server",
  "value": "...",
  "weight": 0.4
}
```

или:

```json
{
  "type": "rtsp_server",
  "value": "...",
  "weight": 0.8
}
```

или:

```json
{
  "type": "onvif_device_info",
  "manufacturer": "...",
  "model": "...",
  "weight": 1.0
}
```

Это позволит объяснять пользователю:

> Почему scanner решил, что это Hikvision?

---

# 66. RESULT EXAMPLE

Финальный объект должен выглядеть примерно так:

```json
{
  "host": "192.168.1.50",

  "device": {
    "type": "nvr",
    "vendor": "Hikvision",
    "model": "...",
    "firmware": "...",
    "confidence": 0.97
  },

  "ports": [
    {
      "port": 80,
      "transport": "tcp",
      "service": "http"
    },
    {
      "port": 554,
      "transport": "tcp",
      "service": "rtsp"
    },
    {
      "port": 3702,
      "transport": "udp",
      "service": "ws-discovery"
    }
  ],

  "services": [],

  "endpoints": [],

  "channels": [],

  "streams": [],

  "authentication": [],

  "fingerprints": [],

  "evidence": []
}
```

---

# 67. UI / SCAN JOB

Web panel должна позволять выбирать:

## Targets

```text
IP
CIDR
ranges
exclusions
Network ID
```

## Port discovery

```text
Top 100
Top 1000
Custom
1–65535
TCP
UDP
```

## Protocol families

```text
Video
Voice
Web
Network
IoT
Industrial
Physical Security
Printers
Storage
Medical
Building Automation
Energy
Transport
```

## Depth

```text
Fast
Standard
Full
Deep
```

## Authentication

```text
Credential list
```

## Performance

```text
Workers
Rate limit
Timeout
Retries
Queue size
Endpoint budget
```

## Safety

```text
Read-only
Allow active protocol probes
Allow supplied credential authentication
```

---

# 68. SCAN RESULT UI

Для каждого IP отображать:

```text
192.168.1.50

Hikvision NVR
Confidence 97%

Ports
80 HTTP
443 HTTPS
554 RTSP
3702 WS-Discovery
8000 SDK

Services
HTTP
HTTPS
RTSP
ONVIF
SDK

Devices
NVR
  ├── Camera 1
  ├── Camera 2
  ├── Camera 3
  └── ...

Streams
Camera 1
  ├── Main H264
  └── Sub H264

Authentication
Digest

Evidence
...
```

---

# 69. SEARCH / FILTERING

В панели должны быть фильтры:

```text
IP
Vendor
Model
Device type
Protocol
Port
Service
Authentication
Firmware
Confidence
Stream codec
Camera
NVR
Printer
Router
PLC
SCADA
```

---

# 70. EXPORT

Поддержать:

```text
JSON
CSV
NDJSON
PDF report
```

Для API предоставить machine-readable JSON.

---

# 71. API

Предусмотреть API:

```text
POST /scans
GET /scans/{id}
POST /scans/{id}/pause
POST /scans/{id}/resume
POST /scans/{id}/cancel

GET /hosts
GET /hosts/{id}

GET /services
GET /devices
GET /streams
GET /endpoints
GET /fingerprints
```

---

# 72. REAL-TIME EVENTS

Во время сканирования отдавать события:

```text
host_discovered
port_open
service_detected
protocol_detected
fingerprint_detected
endpoint_found
authentication_detected
credential_valid
device_detected
stream_found
scan_completed
```

Использовать:

* WebSocket;
* SSE;
* или другой подходящий realtime mechanism.

---

# 73. ROADMAP

Разработку вести по этапам.

## Phase 1 — Core

Сделать:

```text
Target parser
Host discovery
TCP scanner
UDP scanner
Port model
Service model
Job queue
Workers
Rate limiting
```

Результат:

```text
IP → open ports
```

---

## Phase 2 — Service Detection

Добавить:

```text
HTTP
HTTPS
TLS
SSH
FTP
SMTP
DNS
SNMP
SMB
Telnet
```

Результат:

```text
IP → Port → Service → Product
```

Использовать extensible probe database.

---

## Phase 3 — Protocol Framework

Создать plugin architecture:

```text
ProtocolDetector
ProtocolEnumerator
FingerprintProvider
EndpointProvider
AuthProvider
```

---

## Phase 4 — Video

Сначала реализовать:

```text
RTSP
RTP
RTCP
RTMP
HLS
MJPEG
ONVIF
WS-Discovery
```

Особое внимание:

```text
RTSP endpoint corpus
vendor profiles
NVR channel discovery
multi-stream discovery
```

---

## Phase 5 — Web

Добавить:

```text
HTTP
HTTPS
WebSocket
WebDAV
HLS
HTTP-FLV
REST APIs
OpenAPI
Swagger
```

---

## Phase 6 — Voice

Добавить:

```text
SIP
SIP-TLS
RTP
RTCP
IAX
```

---

## Phase 7 — Infrastructure

Добавить:

```text
SNMP
SSH
Telnet
DNS
DHCP
NTP
mDNS
SSDP
LLDP
CDP
SMB
NFS
IPP
```

---

## Phase 8 — IoT

Добавить:

```text
MQTT
CoAP
UPnP
```

---

## Phase 9 — Industrial

Добавить:

```text
Modbus TCP
OPC UA
BACnet/IP
DNP3
EtherNet/IP
S7
PROFINET
IEC 60870-5-104
```

Только safe/read-only.

---

## Phase 10 — Physical Security

Добавить:

```text
Access Control
Intercom
Door systems
ANPR
Parking
Traffic
Barriers
```

---

## Phase 11 — Enterprise / Infrastructure

Добавить:

```text
Routers
Switches
Firewalls
Wi-Fi AP
Wireless bridges
KVM
NAS
UPS
Printers
```

---

## Phase 12 — Specialized

Добавить:

```text
EV chargers
Solar inverters
Telematics
Satellite
Robotics
Drones
Laboratory
Medical
Hotel systems
ATM/POS
```

---

## Phase 13 — Fingerprint Intelligence

Создать:

```text
Vendor DB
Product DB
Model DB
Firmware DB
Protocol DB
Endpoint corpus
Fingerprint correlation engine
Confidence scoring
Evidence engine
```

---

## Phase 14 — Correlation

Научить систему понимать:

```text
IP
 ↓
NVR
 ↓
16 cameras
 ↓
32 streams
```

или:

```text
IP
 ↓
PBX
 ↓
SIP
 ↓
RTP
```

или:

```text
IP
 ↓
Router
 ↓
HTTP
SSH
SNMP
TR-069
```

---

## Phase 15 — UI

Сделать полноценную web panel:

```text
New Scan
Targets
Ports
Protocols
Depth
Credentials
Workers
Rate limits
Safety
```

И отдельные страницы:

```text
Hosts
Devices
Services
Streams
Endpoints
Fingerprints
Credentials
Scan jobs
Reports
```

---

# 74. TESTING

Создать test environment.

Не тестировать scanner только на случайных production devices.

Использовать:

```text
Docker
VM
test cameras
mock RTSP
mock HTTP
mock SIP
mock SNMP
mock MQTT
mock Modbus
mock OPC UA
```

Для каждого protocol plugin иметь:

```text
positive test
negative test
unknown response test
timeout test
authentication test
malformed response test
```

---

# 75. EXTENSIBILITY

Самое важное архитектурное требование:

Добавление нового производителя не должно требовать изменения core scanner.

Например:

```text
Добавили новый Hikvision profile
```

→ core не меняется.

Или:

```text
Добавили новый protocol
```

→ добавляется plugin.

Например:

```text
plugins/
    rtsp/
    onvif/
    sip/
    modbus/
```

---

# 76. ПРОИЗВОДИТЕЛЬНОСТЬ

Не выполнять все проверки сразу.

Использовать adaptive pipeline:

```text
Port open
 ↓
HTTP detected
 ↓
HTTP fingerprint
 ↓
Hikvision detected
 ↓
load Hikvision profile
 ↓
RTSP/ONVIF checks
```

То есть результаты предыдущих стадий должны влиять на следующие.

Это позволит не отправлять тысячи бессмысленных probes на каждый IP.

---

# 77. ADAPTIVE SCANNING

Пример:

```text
554 → RTSP
      ↓
Hikvision
      ↓
load Hikvision RTSP corpus
      ↓
generate candidates
      ↓
probe candidates
```

Если:

```text
554 → not RTSP
```

RTSP-specific deep enumeration не выполнять.

Если:

```text
HTTP → printer fingerprint
```

запускать printer enrichment.

Если:

```text
SNMP → Cisco fingerprint
```

запускать Cisco-specific enrichment.

---

# 78. DISCOVERY BUDGET

Каждый модуль должен иметь:

```text
probe_budget
endpoint_budget
time_budget
connection_budget
```

Например:

```text
Host
 ├── Port scan budget
 ├── Service detection budget
 ├── Protocol budget
 └── Endpoint budget
```

Это необходимо для масштабирования на тысячи IP.

---

# 79. CACHE

Кэшировать:

* fingerprints;
* DNS;
* TLS;
* vendor profiles;
* endpoint candidates;
* known services;
* protocol responses.

Но не кэшировать credentials в открытом виде.

---

# 80. CREDENTIAL SECURITY

Пароли никогда не должны:

* попадать в logs;
* попадать в обычные scan events;
* сохраняться plaintext;
* отображаться в UI после ввода.

Хранить:

```text
encrypted credentials
```

или использовать их только in-memory во время scan.

---

# 81. FINAL RESULT

Главный результат работы системы:

```text
Не:

192.168.1.50
554 OPEN

А:

192.168.1.50

Device:
Hikvision NVR

Model:
...

Firmware:
...

Confidence:
97.4%

Services:
HTTP
HTTPS
RTSP
ONVIF
SDK

Channels:
16

Streams:
32 discovered

Authentication:
Digest

Credentials:
authorized credential #3 → valid

Evidence:
RTSP Server
ONVIF DeviceInformation
HTTP fingerprint
SDK port
Endpoint pattern
Firmware signature
```

---

# 82. ГЛАВНЫЙ АЛГОРИТМ

Итоговая логика должна быть:

```text
                    TARGET IP
                       │
                       ▼
               ┌───────────────┐
               │ HOST DISCOVERY │
               └───────┬───────┘
                       │
                       ▼
               ┌───────────────┐
               │ PORT DISCOVERY│
               └───────┬───────┘
                       │
                       ▼
               ┌───────────────┐
               │SERVICE DETECT │
               └───────┬───────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        HTTP          RTSP         SIP
          │            │            │
          ▼            ▼            ▼
      Fingerprint  Fingerprint  Fingerprint
          │            │            │
          └────────────┼────────────┘
                       ▼
               ┌───────────────┐
               │DEVICE ENGINE  │
               └───────┬───────┘
                       │
                       ▼
               Vendor / Model
                       │
                       ▼
               ┌───────────────┐
               │ENDPOINT ENGINE│
               └───────┬───────┘
                       │
                       ▼
              Endpoint discovery
                       │
                       ▼
              Auth with supplied
                 credentials
                       │
                       ▼
             Deep read-only enum
                       │
                       ▼
               ┌───────────────┐
               │  CORRELATION  │
               └───────┬───────┘
                       │
                       ▼
               FINAL INVENTORY
```

---

# 83. КРИТЕРИЙ УСПЕХА

Система считается успешно реализованной не тогда, когда она быстро сканирует 65 535 портов.

Она считается успешно реализованной, когда для одного IP она способна построить максимально подробную картину:

```text
HOST
│
├── PORTS
│
├── SERVICES
│
├── PROTOCOLS
│
├── PRODUCTS
│
├── VENDORS
│
├── MODELS
│
├── FIRMWARE
│
├── AUTHENTICATION
│
├── ENDPOINTS
│
├── DEVICES
│
├── CHANNELS
│
├── STREAMS
│
└── EVIDENCE
```

Главная цель проекта:

> **Не просто найти открытые порты, а максимально полно реконструировать доступную сетевую поверхность устройства или инфраструктуры на основе безопасного service detection, protocol enumeration, endpoint discovery, fingerprinting и cross-service correlation.**

Все активные protocol probes по умолчанию должны быть read-only и безопасными. Любые операции, способные изменить состояние физического, промышленного, медицинского, транспортного или сетевого оборудования, должны быть явно исключены из стандартного режима.

При реализации сначала разработать:

1. архитектуру core scanner;
2. data model;
3. plugin interface;
4. scan pipeline;
5. service detection engine;
6. fingerprint engine;
7. endpoint engine;
8. credential/authentication engine;
9. correlation engine;
10. fingerprint/endpoint database;
11. protocol plugins;
12. UI/API;
13. testing environment.

Не зашивать vendor-specific логику в core.

Все vendor/model/endpoint fingerprints должны находиться в расширяемой базе данных.

Сделать архитектуру таким образом, чтобы через год можно было добавить новый протокол или производителя без переписывания scanner core.
