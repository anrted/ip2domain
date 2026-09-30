"""Exhaustive device classification and signature catalog for Scanner v2.

Covers 16 major operational technology, IoT, security, and computing domains:
- Video / CCTV / VMS / Streaming
- VoIP / IP Phones / PBX / Intercoms / Audio
- Access Control / Doorphones / Turnstiles / Gates / Barriers
- Industrial / PLC / SCADA / HMI
- Energy / UPS / Meters / Inverters / EV Charging
- IoT / Sensors / Weather / Smart Home
- Traffic / ANPR / Parking / Road Controllers
- Building Automation (BMS) / HVAC
- Fire Alarms / Safety Systems
- Elevators / Dispatchers
- Workplace / Printers / MFPs / 3D Printers
- IP-KVM / IPMI / BMC
- Network / Radio Bridges / Wi-Fi / Satellites / Drones
- Telematics / GPS/GLONASS Trackers
- Specialized / POS / Payment Terminals / Kiosks
- Medical / PACS / DICOM
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

CATEGORY_META: Dict[str, Dict[str, str]] = {
    "video": {"label": "Видеонаблюдение / CCTV", "icon": "📹"},
    "access": {"label": "СКУД / Домофоны / Ворота", "icon": "🚪"},
    "voice": {"label": "IP-Телефония / АТС / Звук", "icon": "📞"},
    "industrial": {"label": "ПЛК / SCADA / АСУ ТП", "icon": "🏭"},
    "energy": {"label": "ИБП / Электропитание / Счётчики", "icon": "🔋"},
    "iot": {"label": "Датчики / IoT / Метео", "icon": "🌡️"},
    "traffic": {"label": "ANPR / Дорожные системы / Парковка", "icon": "🚗"},
    "bms": {"label": "BMS / Умное здание / HVAC", "icon": "🎛️"},
    "safety": {"label": "Пожарные панели / ОПС", "icon": "🚨"},
    "elevator": {"label": "Лифтовое оборудование", "icon": "🛗"},
    "workplace": {"label": "Принтеры / МФУ / 3D-печать", "icon": "🖨️"},
    "ip_kvm": {"label": "IP-KVM / IPMI / Серверы", "icon": "💻"},
    "network": {"label": "Радиомосты / Беспроводное / Сеть", "icon": "📡"},
    "telematics": {"label": "GPS/GLONASS / Телематика", "icon": "🛰️"},
    "specialized": {"label": "POS / Кассы / Терминалы", "icon": "🛒"},
    "medical": {"label": "Медицинское / PACS / DICOM", "icon": "🏥"},
}


@dataclass(frozen=True)
class DeviceRule:
    category: str
    device_type: str
    type_label: str
    vendor: str
    model: str
    signatures: Tuple[str, ...]
    ports: Tuple[int, ...] = ()
    confidence: float = 0.90
    web_path: str = "/"
    snapshot_path: str = ""
    stream_path: str = ""
    telemetry_path: str = ""
    api_path: str = ""


# Comprehensive rule catalog
SIGNATURE_RULES: Tuple[DeviceRule, ...] = (
    # ── 1. Video / CCTV / VMS / Streaming ─────────────────────────────
    DeviceRule("video", "vms", "Система видеонаблюдения (VMS)", "Milestone", "XProtect",
               ("milestone", "xprotect", "surveillancemobile"), (80, 443, 7563, 8081), 0.95,
               "/index.html", "", "/XProtectMobile/Live", "", "/rest/v1"),
    DeviceRule("video", "vms", "Медиа-сервер видеостриминга", "Flussonic", "Media Server",
               ("flussonic",), (80, 8080, 443), 0.95,
               "/admin", "", "/live/index.m3u8", "/flussonic/api/server", "/flussonic/api"),
    DeviceRule("video", "vms", "Система видеонаблюдения (VMS)", "ZoneMinder", "VMS Server",
               ("zoneminder", "zm/index.php"), (80, 443), 0.92,
               "/zm/", "/cgi-bin/nph-zms?mode=single", "/cgi-bin/nph-zms?mode=jpeg", "", "/zm/api"),
    DeviceRule("video", "vms", "Система видеонаблюдения (VMS)", "Trassir", "Video Server",
               ("trassir", "dssl"), (80, 443, 8080), 0.92,
               "/", "", "", "", "/health"),
    DeviceRule("video", "vms", "Система видеонаблюдения (VMS)", "Macroscop", "Video Server",
               ("macroscop",), (80, 443, 8080), 0.92,
               "/site/", "", "/stream/channel", "", "/api"),
    DeviceRule("video", "audio_recorder", "Система аудиозаписи", "SpRecord", "Audio Recorder",
               ("sprecord",), (80, 443, 8080), 0.95,
               "/", "", "/audio", "/status", "/api"),
    DeviceRule("video", "camera", "IP-Камера видеонаблюдения", "Hikvision / HiWatch", "IP Camera / NVR",
               ("hikvision", "hiwatch", "hikvision-webs", "doc/page/login.asp", "logincontroller", "login.asp", "ds-2cd", "ds-72", "ds-76", "ds-77", "ds-96"), (80, 443, 554, 8000), 0.95,
               "/doc/page/login.asp", "/ISAPI/Streaming/channels/101/picture", "/Streaming/Channels/101", "/ISAPI/System/status", "/ISAPI"),
    DeviceRule("video", "camera", "IP-Камера / Видеосервер", "Generic IP Camera", "IP Camera (GoAhead)",
               ("goahead-webs", "newie/css/main.css"), (80, 8080, 554), 0.92,
               "/login.asp", "/snapshot.jpg", "/live/ch0", "", ""),
    DeviceRule("video", "camera", "IP-Камера видеонаблюдения", "Dahua", "IP Camera / NVR",
               ("dahua", "dh-ipc", "dh-xvr", "dh-nvr"), (80, 443, 554, 37777), 0.95,
               "/", "/cgi-bin/snapshot.cgi", "/cam/realmonitor?channel=1&subtype=0", "", "/cgi-bin/magicBox.cgi"),
    DeviceRule("video", "camera", "IP-Камера видеонаблюдения", "Axis", "IP Camera",
               ("axis-camera", "axis-media", "axis communications"), (80, 443, 554), 0.95,
               "/", "/axis-cgi/jpg/image.cgi", "/axis-media/media.amp", "", "/axis-cgi/param.cgi"),
    DeviceRule("video", "camera", "IP-Камера видеонаблюдения", "Uniview", "IP Camera / NVR",
               ("uniview", "unv"), (80, 443, 554), 0.92,
               "/", "/LAPI/V1.0/Channels/0/Media/Video/Source/0/Snapshot", "/unicast/c1/s0/live", "", "/LAPI"),
    DeviceRule("network", "router", "Сетевой маршрутизатор / Wi-Fi Роутер", "D-Link", "Wireless Router",
               ("d-link", "dlink", "wireless router", "css_router.css"), (80, 8080, 443), 0.95,
               "/", "", "", "/status.htm", ""),

    # ── 2. Access Control / Doorphones / Turnstiles / Gates ────────────
    DeviceRule("access", "doorphone", "IP-Домофон / Вызывная панель", "Beward", "DKS / Intercom",
               ("beward", "dks15120", "dks20210", "dks850"), (80, 443, 554), 0.95,
               "/", "/cgi-bin/images_cgi?channel=0", "/live/ch0", "", "/cgi-bin/operator/system.cgi"),
    DeviceRule("access", "doorphone", "IP-Домофон / Вызывная панель", "BAS-IP", "Multi-Apartment Intercom",
               ("bas-ip", "aa-07b", "av-01b", "av-07b"), (80, 443, 554, 8080), 0.95,
               "/", "/snap.jpg", "/live/ch0", "", "/api/v1/door/open"),
    DeviceRule("access", "doorphone", "IP-Домофон / Вызывная панель", "True IP", "IP Intercom",
               ("true ip", "trueip", "ti-2600", "ti-3000"), (80, 443, 554), 0.95,
               "/", "/snapshot.jpg", "/cam/realmonitor?channel=1&subtype=0", "", "/cgi-bin/accessControl.cgi"),
    DeviceRule("access", "doorphone", "IP-Домофон / Интерком", "2N", "Helios IP",
               ("2n helios", "2n ip", "2n telecommunications"), (80, 443, 554), 0.95,
               "/", "/api/camera/snapshot", "/h264_stream", "", "/api/switch/ctrl"),
    DeviceRule("access", "doorphone", "IP-Домофон / Вызывная панель", "Akuvox", "Smart Intercom",
               ("akuvox",), (80, 443, 554), 0.95,
               "/", "/fcgi/do?action=snapshot", "/live/ch0", "", "/fcgi/do?action=open_door"),
    DeviceRule("access", "access_controller", "СКУД / Контроллер доступа", "Sigur", "Access Controller",
               ("sigur", "сфинкс", "e500", "e300"), (80, 443, 3306, 8080), 0.95,
               "/", "", "", "/status", "/api"),
    DeviceRule("access", "access_controller", "СКУД / Биометрический терминал", "ZKTeco", "Biometric Terminal",
               ("zkteco", "zksoftware", "inbio", "speedface"), (80, 443, 4370, 8088), 0.95,
               "/", "", "", "", "/api"),
    DeviceRule("access", "access_controller", "СКУД / Контроллер доступа", "Parsec", "Network Controller",
               ("parsec", "nc-8000", "nc-32k"), (80, 443, 10001), 0.90,
               "/", "", "", "/parsec/status", ""),
    DeviceRule("access", "access_controller", "СКУД / Контроллер турникетов", "Perco", "Turnstile Controller",
               ("perco", "ct/l04", "cr01"), (80, 443, 8080), 0.92,
               "/", "", "", "", "/api"),
    DeviceRule("access", "gate_controller", "Контроллер ворот / шлагбаума", "CAME / Nice", "Gate Controller",
               ("came connect", "nice gate", "cobox", "pal-es"), (80, 443, 8080), 0.90,
               "/", "", "", "/status", "/api/relay"),

    # ── 3. VoIP / IP Phones / PBX / Audio / Dispatch ──────────────────
    DeviceRule("voice", "pbx", "IP-АТС / Телефония", "FreePBX / Asterisk", "PBX Server",
               ("freepbx", "asterisk", "sangoma"), (80, 443, 5060, 5038, 8088), 0.95,
               "/admin/", "", "", "/admin/config.php?display=dashboard", "/ari"),
    DeviceRule("voice", "pbx", "IP-АТС / Телефония", "3CX", "Phone System",
               ("3cx", "3cxphonesystem"), (80, 443, 5060, 5001, 5015), 0.95,
               "/#/login", "", "", "", "/api"),
    DeviceRule("voice", "pbx", "IP-АТС / Softswitch", "FreeSWITCH", "Telephony Engine",
               ("freeswitch",), (80, 443, 5060, 8021), 0.92,
               "/", "", "", "", "/event_socket"),
    DeviceRule("voice", "pbx", "IP-АТС / Офисная телефония", "Yeastar", "MyPBX / S-Series",
               ("yeastar", "mypbx"), (80, 443, 5060, 8088), 0.95,
               "/", "", "", "", "/api/v1.1.0"),
    DeviceRule("voice", "ip_phone", "IP-Телефон", "Yealink", "SIP Phone",
               ("yealink", "sip-t"), (80, 443, 5060), 0.95,
               "/", "/screencapture", "", "", "/servlet?p=login"),
    DeviceRule("voice", "ip_phone", "IP-Телефон", "Grandstream", "GXP / GRP IP Phone",
               ("grandstream", "gxp", "grp26"), (80, 443, 5060), 0.95,
               "/", "/jpeg/view.html", "", "", "/cgi-bin/api-sys_operation"),
    DeviceRule("voice", "ip_phone", "IP-Телефон", "Cisco", "Unified IP Phone",
               ("cisco systems", "cisco ip phone", "cp-79", "cp-88"), (80, 443, 5060), 0.95,
               "/", "", "", "/NetworkConfiguration", "/Cisco/"),
    DeviceRule("voice", "ip_audio", "IP-Громкоговоритель / Аудиоинтерком", "Barix", "Annuncicom / Exstreamer",
               ("barix", "annuncicom", "exstreamer"), (80, 443, 8000), 0.95,
               "/", "", "/broadcast", "/status", ""),

    # ── 4. Industrial / PLC / SCADA / HMI ─────────────────────────────
    DeviceRule("industrial", "plc", "Промышленный контроллер (ПЛК)", "Siemens", "SIMATIC S7-1200 / S7-1500",
               ("simatic", "s7-1200", "s7-1500", "s7-300", "s7-400", "s7comm"), (80, 443, 102), 0.98,
               "/Portal/Portal.mwsl", "", "", "/Portal/Portal.mwsl?App=Diagnostic", "s7://"),
    DeviceRule("industrial", "plc", "Промышленный контроллер (ПЛК)", "Rockwell Automation / Allen-Bradley", "ControlLogix / CompactLogix",
               ("rockwell", "allen-bradley", "controllogix", "compactlogix", "enip", "ethernet/ip"), (44818, 2222, 80, 443), 0.95,
               "/", "", "", "/diagnostics", "enip://"),
    DeviceRule("industrial", "plc", "Промышленный контроллер (ПЛК)", "Schneider Electric", "Modicon M340 / M580",
               ("schneider electric", "modicon", "telemecanique"), (80, 443, 502), 0.95,
               "/index.htm", "", "", "/diag.htm", "modbus://"),
    DeviceRule("industrial", "plc", "Промышленный контроллер (ПЛК)", "Omron", "Sysmac / FINS",
               ("omron", "sysmac", "cj2m", "nj501"), (80, 443, 9600), 0.92,
               "/", "", "", "", "fins://"),
    DeviceRule("industrial", "plc", "Промышленный контроллер (ПЛК)", "WAGO", "PFC200 / I/O System",
               ("wago", "pfc200", "750-8"), (80, 443, 502), 0.95,
               "/wbm/", "", "", "/wbm/index.php", "modbus://"),
    DeviceRule("industrial", "scada", "SCADA / HMI Панель оператора", "Siemens", "WinCC / Comfort Panel",
               ("wincc", "simatic hmi"), (80, 443, 5800, 5900), 0.95,
               "/", "", "", "", "/Miniweb"),
    DeviceRule("industrial", "scada", "SCADA / HMI Система", "Inductive Automation", "Ignition SCADA",
               ("ignition", "inductive automation"), (80, 443, 8088, 8043), 0.95,
               "/web/status", "", "", "/web/status/sys.overview", "/main/system/api"),
    DeviceRule("industrial", "plc", "Промышленный шлюз интерфейсов", "Moxa", "NPort / ioLogik",
               ("moxa", "nport", "iologik", "edr-"), (80, 443, 502, 4001), 0.95,
               "/home.htm", "", "", "/status.htm", ""),
    DeviceRule("industrial", "plc", "Промышленный контроллер (ПЛК)", "OWEN (Овен)", "ПЛК / ТРМ",
               ("owen", "овен", "плк110", "плк210"), (80, 443, 502, 1200), 0.95,
               "/", "", "", "", "modbus://"),

    # ── 5. Energy / UPS / Meters / Inverters / EV Charging ────────────
    DeviceRule("energy", "ups", "Источник бесперебойного питания (ИБП)", "APC by Schneider Electric", "Smart-UPS / NMC",
               ("apc", "smart-ups", "network management card", "powerchute", "apc web/snmp management card"), (80, 443, 161), 0.98,
               "/home.htm", "", "", "/data.htm", "/rest/v1"),
    DeviceRule("energy", "ups", "Источник бесперебойного питания (ИБП)", "Eaton", "Network Card-MS / Powerware",
               ("eaton", "powerware", "network card-ms"), (80, 443, 161), 0.95,
               "/", "", "", "/environment", ""),
    DeviceRule("energy", "ups", "Источник бесперебойного питания (ИБП)", "CyberPower", "RMCARD / Smart App",
               ("cyberpower", "rmcard"), (80, 443, 161), 0.95,
               "/", "", "", "/status.html", ""),
    DeviceRule("energy", "ups", "Источник бесперебойного питания (ИБП)", "Vertiv / Liebert", "Liebert IntelliSlot / GXT",
               ("vertiv", "liebert", "intellislot"), (80, 443, 161), 0.95,
               "/", "", "", "/monitoring", ""),
    DeviceRule("energy", "meter", "Счётчик электроэнергии", "Меркурий / Инкотекс", "Меркурий 230 / 234 / 236",
               ("меркурий", "mercury", "инкотекс", "incotex"), (80, 443, 1000, 2000, 8000), 0.95,
               "/", "", "", "/data", ""),
    DeviceRule("energy", "meter", "Счётчик электроэнергии", "Энергомера", "СЕ301 / СЕ303 / СЕ308",
               ("энергомера", "ce301", "ce303", "ce308"), (80, 443, 10001), 0.95,
               "/", "", "", "/status", ""),
    DeviceRule("energy", "inverter", "Солнечный инвертор / Энергетика", "SMA Solar", "Sunny Boy / Tripower",
               ("sma solar", "sunny boy", "webconnect"), (80, 443), 0.95,
               "/#/login", "", "", "/dyn/getDashValues.json", "/api"),
    DeviceRule("energy", "ev_charger", "Зарядная станция электромобилей", "ABB / Terra", "EV Charger / OCPP",
               ("terra 54", "terra 53", "ocpp", "evlink"), (80, 443, 8887), 0.95,
               "/", "", "", "/status", "/ocpp"),

    # ── 6. IoT / Sensors / Weather / Smart Home ───────────────────────
    DeviceRule("iot", "sensor", "Сетевой датчик температуры/влажности", "HW group", "Poseidon / Damocles",
               ("hw group", "poseidon", "damocles"), (80, 443, 161), 0.95,
               "/", "", "", "/values.xml", "/values.json"),
    DeviceRule("iot", "sensor", "Сетевой контроллер датчиков", "Tibbo", "EM1000 / Sensor Hub",
               ("tibbo", "em1000", "tps"), (80, 443, 65432), 0.92,
               "/", "", "", "/status.html", ""),
    DeviceRule("iot", "sensor", "Метеостанция / Датчики микроклимата", "Netatmo", "Weather Station",
               ("netatmo",), (80, 443), 0.90,
               "/", "", "", "/status", "/api"),
    DeviceRule("iot", "smart_home", "Хаб домашней автоматизации", "Home Assistant", "Smart Home Hub",
               ("home assistant", "home-assistant"), (8123, 80, 443), 0.98,
               "/", "", "", "", "/api/websocket"),
    DeviceRule("iot", "smart_home", "Интеграционный хаб IoT", "Node-RED", "Flow Editor",
               ("node-red",), (1880, 80), 0.95,
               "/", "", "", "", "/flows"),

    # ── 7. Traffic / ANPR / Parking / Road Controllers ────────────────
    DeviceRule("traffic", "anpr", "Комплекс фотовидеофиксации / ANPR", "АвтоУраган / Поток", "LPR Camera",
               ("автоураган", "поток", "parkon", "autouragan"), (80, 443, 554), 0.95,
               "/", "/snap.jpg", "/live/ch0", "/status", "/api/plates"),
    DeviceRule("traffic", "traffic_controller", "Дорожный контроллер светофоров", "SWARCO / Peek", "ITC-2 / Traffic Controller",
               ("swarco", "itc-2", "peek traffic", "асудд"), (80, 443, 161), 0.95,
               "/", "", "", "/diag", ""),
    DeviceRule("traffic", "parking", "Парковочная система / Касса", "Паркнефть / ПаркТайм", "Parking Terminal",
               ("parktime", "парктайм", "вектор"), (80, 443, 8080), 0.92,
               "/", "", "", "/status", "/api"),

    # ── 8. Building Automation (BMS) / HVAC ───────────────────────────
    DeviceRule("bms", "bms", "Система автоматизации здания (BMS)", "Tridium", "Niagara Framework",
               ("niagara", "tridium", "jace"), (80, 443, 502, 1911), 0.98,
               "/login/", "", "", "/ord/", "/api"),
    DeviceRule("bms", "bms", "BMS Контроллер здания", "Johnson Controls", "Metasys / Facility Explorer",
               ("metasys", "johnson controls"), (80, 443), 0.95,
               "/login.html", "", "", "", ""),
    DeviceRule("bms", "bms", "Система автоматизации здания (BACnet)", "BACnet BMS", "Building Automation Controller",
               ("bacnet", "bacnet/ip"), (47808, 80, 443), 0.95,
               "/", "", "", "", "bacnet://"),

    # ── 9. Fire Alarms / Safety Systems ───────────────────────────────
    DeviceRule("safety", "fire_panel", "Охранно-пожарная панель", "Bolid (Болид)", "ИСО Орион / С2000-ПП",
               ("болид", "bolid", "с2000", "сириус"), (80, 443, 40000), 0.95,
               "/", "", "", "/state", ""),
    DeviceRule("safety", "fire_panel", "Пожарная панель", "Honeywell / Notifier", "Fire Alarm Panel",
               ("notifier", "honeywell fire", "esser"), (80, 443, 161), 0.95,
               "/", "", "", "", ""),

    # ── 10. Elevators / Dispatchers ───────────────────────────────────
    DeviceRule("elevator", "elevator", "Система мониторинга лифтов", "ЛКДС", "ОБЬ / Диспетчерский комплекс",
               ("лкдс", "обь", "диспетчеризация лифтов"), (80, 443, 8080), 0.95,
               "/", "", "", "/status", ""),
    DeviceRule("elevator", "elevator", "Контроллер лифта", "OTIS / Schindler", "Elevator GCS / Controller",
               ("otis elevator", "schindler elevator", "thyssenkrupp"), (80, 443), 0.92,
               "/", "", "", "", ""),

    # ── 11. Workplace / Printers / MFPs / 3D Printers ─────────────────
    DeviceRule("workplace", "printer", "Сетевой принтер / МФУ", "HP", "LaserJet / OfficeJet",
               ("jetdirect", "hp laserjet", "hp officejet", "hp pagewide"), (80, 443, 631, 9100), 0.98,
               "/", "", "", "/hp/device/this.LCDispatcher", "ipp://"),
    DeviceRule("workplace", "printer", "Сетевой принтер / МФУ", "Xerox", "CentreWare / WorkCentre",
               ("centreware", "workcentre", "xerox corporation"), (80, 443, 631, 9100), 0.98,
               "/index.dhtml", "", "", "/status/statushistory.dhtml", "ipp://"),
    DeviceRule("workplace", "printer", "Сетевой принтер / МФУ", "Canon", "imageRUNNER",
               ("canon imagerunner", "canon advance"), (80, 443, 631, 9100), 0.95,
               "/", "", "", "/portal/status", "ipp://"),
    DeviceRule("workplace", "printer", "Сетевой принтер / МФУ", "Kyocera", "TASKalfa / ECOSYS",
               ("command center rx", "kyocera"), (80, 443, 631, 9100), 0.95,
               "/", "", "", "/startwlm/Hme_Status.htm", "ipp://"),
    DeviceRule("workplace", "3d_printer", "3D-Принтер / Сервер печати", "OctoPrint", "Print Server",
               ("octoprint",), (80, 443, 5000), 0.98,
               "/", "/webcam/?action=snapshot", "/webcam/?action=stream", "", "/api/version"),
    DeviceRule("workplace", "3d_printer", "3D-Принтер / Веб-интерфейс", "Klipper / Moonraker", "Mainsail / Fluidd",
               ("moonraker", "mainsail", "fluidd"), (80, 443, 7125), 0.98,
               "/", "/webcam/?action=snapshot", "/webcam/?action=stream", "/printer/info", "/server/info"),
    DeviceRule("workplace", "nas", "Сетевое хранилище (NAS)", "Synology", "DiskStation (DSM)",
               ("synology", "diskstation"), (5000, 5001, 80, 443), 0.98,
               "/", "", "", "", "/webman/3rdparty/"),
    DeviceRule("workplace", "nas", "Сетевое хранилище (NAS)", "QNAP", "QTS NAS",
               ("qnap", "qts"), (8080, 443, 80), 0.95,
               "/", "", "", "", "/cgi-bin/"),

    # ── 12. IP-KVM / IPMI / Server BMC ────────────────────────────────
    DeviceRule("ip_kvm", "kvm", "Модуль управления сервером", "Dell", "iDRAC",
               ("idrac", "integrated dell remote access controller"), (80, 443, 5900, 623), 0.98,
               "/start.html", "", "", "/sysmgmt/2012/server/status", "/redfish/v1/"),
    DeviceRule("ip_kvm", "kvm", "Модуль управления сервером", "HPE", "iLO (Integrated Lights-Out)",
               ("integrated lights-out", "ilo 4", "ilo 5", "hp ilo"), (80, 443, 17988, 623), 0.98,
               "/login.html", "", "", "", "/redfish/v1/"),
    DeviceRule("ip_kvm", "kvm", "Модуль управления сервером", "Supermicro", "IPMI / BMC",
               ("supermicro", "atens technology", "ipmi 2.0"), (80, 443, 623), 0.95,
               "/", "", "", "/cgi/ipmi.cgi", "/redfish/v1/"),
    DeviceRule("ip_kvm", "kvm", "Аппаратный IP-KVM переключатель", "Aten / Raritan", "IP-KVM Switch",
               ("aten", "raritan", "dominion kx", "kn2116"), (80, 443, 5900), 0.95,
               "/", "", "", "", ""),

    # ── 13. Network / Radio Bridges / Wi-Fi / Satellites / Drones ─────
    DeviceRule("network", "radio_bridge", "Беспроводной радиомост / Точка доступа", "Ubiquiti", "airMAX / UniFi",
               ("airos", "airmax", "nanostation", "powerbeam", "unifi"), (80, 443, 8443, 8080), 0.98,
               "/", "", "", "/status.cgi", "/api"),
    DeviceRule("network", "radio_bridge", "Сетевой маршрутизатор / Радиомост", "MikroTik", "RouterOS",
               ("mikrotik", "routeros"), (80, 443, 8291, 8728), 0.98,
               "/webfig/", "", "", "/graphs/", "/rest/"),
    DeviceRule("network", "satellite_terminal", "Спутниковый терминал / Модем", "iDirect / Hughes", "Satellite Modem",
               ("idirect", "hughesnet", "inmarsat", "hx200"), (80, 443), 0.95,
               "/", "", "", "/status/terminal", ""),
    DeviceRule("network", "drone_station", "Наземная станция БПЛА / Дрона", "MAVLink / QGC", "Ground Control Station",
               ("mavlink", "qgroundcontrol", "dji pilot"), (80, 443, 14550), 0.92,
               "/", "", "/video", "/telemetry", "/api"),

    # ── 14. Telematics / GPS/GLONASS Trackers ─────────────────────────
    DeviceRule("telematics", "telematics", "Сервер мониторинга транспорта", "Traccar", "GPS Tracking Server",
               ("traccar",), (8082, 80, 443), 0.98,
               "/", "", "", "/api/session", "/api/positions"),
    DeviceRule("telematics", "telematics", "Сервер мониторинга транспорта", "Wialon / Gurtam", "Fleet Management",
               ("wialon", "gurtam"), (80, 443, 20222), 0.95,
               "/", "", "", "", "/wialon/ajax.html"),
    DeviceRule("telematics", "telematics", "GPS/GLONASS Трекер", "Teltonika", "FMB / RUT Tracker",
               ("teltonika", "fmb920", "fmb120"), (5027, 80, 443), 0.95,
               "/", "", "", "/status", ""),

    # ── 15. Specialized / POS / Cash Registers / Terminals ────────────
    DeviceRule("specialized", "pos", "Онлайн-касса / Фискальный регистратор", "АТОЛ", "ККТ / Драйвер ККТ",
               ("атол", "atol", "fptr", "эвотор"), (80, 443, 16732, 5555), 0.95,
               "/", "", "", "/status", "/api/v2/operations"),
    DeviceRule("specialized", "pos", "Онлайн-касса / POS-терминал", "Штрих-М", "ККТ / Штрих",
               ("штрих-м", "shtrih", "касса"), (80, 443, 8080), 0.95,
               "/", "", "", "/status", ""),

    # ── 16. Medical / PACS / DICOM ────────────────────────────────────
    DeviceRule("medical", "medical", "Медицинский сервер PACS / DICOM", "Orthanc / DCM4CHEE", "DICOM Server",
               ("orthanc", "dcm4chee", "dicom"), (8042, 80, 443, 104, 11112), 0.98,
               "/app/explorer.html", "", "", "/statistics", "/instances"),
)


def match_device_rule(text: str, open_ports: Tuple[int, ...] = ()) -> Optional[DeviceRule]:
    """Find matching device rule by inspecting banner/server/content text and ports."""
    if not text:
        return None
    lower = text.lower()
    ports_set = set(open_ports)

    best_rule: Optional[DeviceRule] = None
    best_score = 0.0

    for rule in SIGNATURE_RULES:
        for sig in rule.signatures:
            if sig in lower:
                score = rule.confidence
                # Bonus if port aligns with expected device ports
                if ports_set and any(p in ports_set for p in rule.ports):
                    score += 0.05
                if score > best_score:
                    best_score = score
                    best_rule = rule
                break

    return best_rule
