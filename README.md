# Port Scan Detector en

An educational tool for detecting signs of port scanning in network logs. It reads CSV or pcap files, looks for several common behavior patterns, and writes alerts to the console, JSON, and CSV. The project is intended for learning and for testing with data from your own lab.

Detections are mapped to MITRE ATT&CK [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/).

## What the detector looks for

All rules use a sliding time window. By default, the window is 60 seconds and the thresholds are 20 events or unique values:

- **Vertical scan:** one source contacts many unique ports on a single destination address.
- **Horizontal scan:** one source contacts the same port on many destination addresses.
- **SYN without a subsequent ACK:** SYN events accumulate from one source, with no later ACK found in the same direction and flow.

A single traffic flow can match multiple rules and generate multiple alerts. Each alert includes a `mitre` field with the value `T1046`.

## Requirements

- Python 3.11 or later
- PyYAML for reading the configuration
- pytest for running tests
- Scapy — optional package for reading pcap/pcapng files

## Installation

Go to the project directory, create a virtual environment, and install the main dependencies:

```bash
cd portscan-detector
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Make sure `python3 --version` shows Python 3.11 or later. If you have multiple Python versions installed, create the environment with the required version explicitly, for example:

```bash
python3.11 -m venv .venv
```

To read pcap files, install Scapy in the activated environment:

```bash
python -m pip install scapy
```

## CSV format

The CSV file must have a header and columns in this format:

```csv
timestamp,src_ip,dst_ip,dst_port,flags
2026-01-01T12:00:00Z,203.0.113.10,198.51.100.10,443,SYN
```

The `timestamp` field must include the date, time, and time zone. The `flags` field contains TCP flag names, such as `SYN`, `ACK`, or `SYN,ACK`. An invalid row triggers a warning and is skipped. An invalid header or an inaccessible file stops the program with an error message.

## Examples

Run the detector on a CSV file using settings from `config.yaml`:

```bash
PYTHONPATH=src python -m detector.cli \
  --input samples/events.csv \
  --config config.yaml
```

Print a table to the console and save both file reports:

```bash
PYTHONPATH=src python -m detector.cli \
  --input samples/events.csv \
  --config config.yaml \
  --output reports/alerts
```

The command creates `reports/alerts.json` and `reports/alerts.csv`. The input file extension determines which parser is used: `.pcap` and `.pcapng` files are read with Scapy; other extensions are treated as CSV.

Regenerate the sample CSV:

```bash
python samples/generate_samples.py
```

## Example output

Rules can overlap in `samples/events.csv`: the vertical and horizontal scan scenarios also contain SYN events without ACKs. As a result, the example produces more than three alerts.

```text
Rule            | Source IP    | Target                         | Count | First seen                | Last seen                 | MITRE
----------------+--------------+--------------------------------+-------+---------------------------+---------------------------+------
vertical_scan   | 203.0.113.10 | 198.51.100.10                  | 20    | 2026-01-01T12:00:40+00:00 | 2026-01-01T12:01:18+00:00 | T1046
syn_without_ack | 203.0.113.10 | multiple destinations or ports | 20    | 2026-01-01T12:00:40+00:00 | 2026-01-01T12:01:18+00:00 | T1046
horizontal_scan | 203.0.113.20 | destination port 445           | 20    | 2026-01-01T12:01:40+00:00 | 2026-01-01T12:02:18+00:00 | T1046
syn_without_ack | 203.0.113.20 | multiple destinations or ports | 20    | 2026-01-01T12:01:40+00:00 | 2026-01-01T12:02:18+00:00 | T1046
syn_without_ack | 203.0.113.30 | multiple destinations or ports | 20    | 2026-01-01T12:02:40+00:00 | 2026-01-01T12:03:18+00:00 | T1046
```

Times in the report are shown in UTC.

## Configuring thresholds

Open `config.yaml`. For example, to change the window and thresholds, edit the numbers:

```yaml
window_seconds: 60

thresholds:
  vertical_unique_ports: 20
  horizontal_unique_hosts: 20
  syn_without_ack: 20
```

All values must be positive integers.

## Tests

From the project root, with the virtual environment activated, run:

```bash
PYTHONPATH=src python -m pytest -q
```

The tests check that ordinary connections produce no alerts, that each of the three rules detects its scan pattern, and that a malformed CSV row is skipped.

## Lab test with pcap and Nmap

Instructions for capturing your own traffic and comparing `nmap -sS` with `nmap -sT` are in [samples/PCAP_LAB.md](samples/PCAP_LAB.md). Scan only your own virtual machines or systems you have permission to test.

## Limitations

- **Slow scans:** the rules count events only within the configured window. If a scanner spreads its attempts out so the threshold is not reached during that time, the detector may miss it.
- **IPv6:** the parser and pcap reader accept IPv6 TCP addresses, but IPv6 scenarios do not have separate tests. Fragmentation and other IPv6-specific behavior are not analyzed.
- **SYN/ACK matching in CSV:** the format does not include a source port, so matching uses an incomplete set of fields. The source port is available in pcap files, but the result still depends on the completeness and quality of the capture.
- **Threshold heuristics:** alerts are indicators for investigation, not proof of malicious activity. Normal high-volume traffic may also reach a threshold.

## Project structure

```text
portscan-detector/
├── src/detector/
│   ├── parser.py
│   ├── rules.py
│   ├── report.py
│   └── cli.py
├── config.yaml
├── samples/
│   ├── events.csv
│   ├── generate_samples.py
│   └── PCAP_LAB.md
├── tests/
│   └── test_detector.py
├── requirements.txt
├── README.md
└── .gitignore
```

# Port Scan Detector ru

Учебный детектор признаков сканирования портов в сетевых логах. Он читает CSV
или pcap, ищет несколько характерных шаблонов поведения и сохраняет алерты в
консоли, JSON и CSV. Проект предназначен для обучения и проверки на данных из
собственной лаборатории.

Обнаружения связываются с MITRE ATT&CK [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/).

## Что ищет детектор

Все правила работают в скользящем временном окне. По умолчанию окно составляет
60 секунд, а пороги — 20 событий или уникальных значений:

- **Вертикальное сканирование:** один источник обращается к множеству уникальных
  портов на одном адресе назначения.
- **Горизонтальное сканирование:** один источник обращается к одному порту на
  множестве адресов назначения.
- **SYN без последующего ACK:** у одного источника накапливаются SYN-события,
  для которых не найден более поздний ACK в том же направлении и потоке.

Один поток трафика может соответствовать нескольким правилам и породить несколько
алертов. Каждому алерту добавляется поле `mitre` со значением `T1046`.

## Требования

- Python 3.11 или новее
- PyYAML для чтения конфигурации
- pytest для запуска тестов
- Scapy — необязательный пакет для чтения pcap/pcapng

## Установка

Перейди в папку проекта, создай виртуальное окружение и установи основные
зависимости:

```bash
cd portscan-detector
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Убедись, что команда `python3 --version` показывает Python 3.11 или новее. Если
в системе установлено несколько версий Python, создай окружение явно нужной
версией, например:

```bash
python3.11 -m venv .venv
```

Для чтения pcap дополнительно установи Scapy внутри активированного окружения:

```bash
python -m pip install scapy
```

## Формат CSV

CSV-файл должен содержать заголовок и столбцы в таком формате:

```csv
timestamp,src_ip,dst_ip,dst_port,flags
2026-01-01T12:00:00Z,203.0.113.10,198.51.100.10,443,SYN
```

В `timestamp` указывается дата, время и часовой пояс. Поле `flags` содержит имена
TCP-флагов, например `SYN`, `ACK` или `SYN,ACK`. Некорректная строка вызывает
предупреждение и пропускается; ошибка заголовка или недоступный файл останавливают
запуск с сообщением об ошибке.

## Примеры запуска

Запустить детектор на CSV с настройками из `config.yaml`:

```bash
PYTHONPATH=src python -m detector.cli \
  --input samples/events.csv \
  --config config.yaml
```

Показать таблицу в консоли и сохранить оба файловых отчёта:

```bash
PYTHONPATH=src python -m detector.cli \
  --input samples/events.csv \
  --config config.yaml \
  --output reports/alerts
```

Команда создаст `reports/alerts.json` и `reports/alerts.csv`. Расширение входного
файла выбирает парсер автоматически: `.pcap` и `.pcapng` читаются через Scapy,
остальные расширения — как CSV.

Создать учебный CSV заново:

```bash
python samples/generate_samples.py
```

## Пример вывода

На `samples/events.csv` правила могут пересекаться: вертикальные и горизонтальные
сценарии тоже состоят из SYN без ACK. Поэтому пример выводит больше трёх алертов.

```text
Rule            | Source IP    | Target                         | Count | First seen                | Last seen                 | MITRE
----------------+--------------+--------------------------------+-------+---------------------------+---------------------------+------
vertical_scan   | 203.0.113.10 | 198.51.100.10                  | 20    | 2026-01-01T12:00:40+00:00 | 2026-01-01T12:01:18+00:00 | T1046
syn_without_ack | 203.0.113.10 | multiple destinations or ports | 20    | 2026-01-01T12:00:40+00:00 | 2026-01-01T12:01:18+00:00 | T1046
horizontal_scan | 203.0.113.20 | destination port 445           | 20    | 2026-01-01T12:01:40+00:00 | 2026-01-01T12:02:18+00:00 | T1046
syn_without_ack | 203.0.113.20 | multiple destinations or ports | 20    | 2026-01-01T12:01:40+00:00 | 2026-01-01T12:02:18+00:00 | T1046
syn_without_ack | 203.0.113.30 | multiple destinations or ports | 20    | 2026-01-01T12:02:40+00:00 | 2026-01-01T12:03:18+00:00 | T1046
```

Времена в отчёте показаны в UTC.

## Настройка порогов

Открой `config.yaml`. Например, чтобы менять окно и пороги, отредактируй числа:

```yaml
window_seconds: 60

thresholds:
  vertical_unique_ports: 20
  horizontal_unique_hosts: 20
  syn_without_ack: 20
```

Все значения должны быть положительными целыми числами.

## Тесты

Из корня проекта с активированным виртуальным окружением запусти:

```bash
PYTHONPATH=src python -m pytest -q
```

Тесты проверяют обычные соединения без алертов, обнаружение каждого из трёх
правил и пропуск испорченной строки CSV.

## Лабораторная проверка pcap и Nmap

Инструкция по захвату своего трафика и сравнению `nmap -sS` с `nmap -sT` находится
в [samples/PCAP_LAB.md](samples/PCAP_LAB.md). Сканируй только собственные
виртуальные машины или системы, на проверку которых у тебя есть разрешение.

## Ограничения

- **Медленное сканирование:** правила считают события только внутри настроенного
  окна. Если сканер распределит попытки так, что порог не будет достигнут за это
  время, детектор может его пропустить.
- **IPv6:** парсер и pcap-ридер принимают IPv6 TCP-адреса, но IPv6-сценарии не
  покрыты отдельными тестами. Фрагментация и другие особенности IPv6 отдельно не
  анализируются.
- **Сопоставление SYN/ACK в CSV:** формат не содержит исходный порт, поэтому
  сопоставление использует неполный набор полей. В pcap исходный порт доступен,
  но результат всё равно зависит от полноты и качества захвата.
- **Пороговые эвристики:** срабатывания — признаки для анализа, а не доказательство
  вредоносной активности. Обычный интенсивный трафик также может достичь порога.

## Структура проекта

```text
portscan-detector/
├── src/detector/
│   ├── parser.py
│   ├── rules.py
│   ├── report.py
│   └── cli.py
├── config.yaml
├── samples/
│   ├── events.csv
│   ├── generate_samples.py
│   └── PCAP_LAB.md
├── tests/
│   └── test_detector.py
├── requirements.txt
├── README.md
└── .gitignore
```
