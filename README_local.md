# ML Course in InfoSec - Homework Task 4

## Задание

Автоматическая обработка правил корреляции для SIEM-систем с использованием LLM:
1. **Нормализация событий** - преобразование Windows событий в унифицированную схему полей SIEM
2. **Классификация MITRE ATT&CK** - определение тактики, техники и важности
3. **Генерация локализаций** - создание файлов i18n (английский и русский)

## Структура решения

```
.
├── process_correlations.py       # Task 1: Нормализация событий
├── classify_and_localize.py      # Tasks 2 & 3: Классификация и локализация (LLM)
├── run_homework.py               # Главный скрипт запуска
├── README.md                     # Эта инструкция
├── windows_correlation_rules/    # Входные данные и результаты
│   ├── correlation_1/
│   │   ├── tests/
│   │   │   ├── events_1_1.json           # Входные события (сырые)
│   │   │   └── norm_fields_1_1.json      # ✅ Нормализованные поля (Task 1)
│   │   ├── answers.json                  # ✅ MITRE классификация (Task 2)
│   │   └── i18n/
│   │       ├── i18n_en.yaml              # ✅ Локализация EN (Task 3)
│   │       └── i18n_ru.yaml              # ✅ Локализация RU (Task 3)
│   ├── correlation_2/
│   └── ...
├── macos_correlation_rules/      # Примеры для Few-Shot обучения
└── taxonomy_fields/              # Схема полей SIEM
    ├── i18n_en.yaml
    └── i18n_ru.yaml
```

## Установка зависимостей

```bash
# Создать виртуальное окружение
python3 -m venv .venv
source .venv/bin/activate

# Установить зависимости
pip install pyyaml anthropic openai pypdf
```

## Настройка API ключа

Для задач 2 и 3 требуется доступ к LLM. Поддерживаются:

### Вариант 1: Anthropic Claude (рекомендуется)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Вариант 2: OpenAI GPT-4
```bash
export OPENAI_API_KEY="sk-..."
```

### Вариант 3: OpenRouter (мультимодельный провайдер)
```bash
# Отредактируйте classify_and_localize.py и замените:
# client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
# на:
# client = openai.OpenAI(
#     base_url="https://openrouter.ai/api/v1",
#     api_key=os.getenv("OPENROUTER_API_KEY")
# )
```

## Запуск

### Быстрый запуск (все задачи)
```bash
python run_homework.py
```

Скрипт выполнит:
1. Нормализацию всех событий (Task 1)
2. Классификацию MITRE ATT&CK через LLM (Task 2)
3. Генерацию локализаций на EN/RU (Task 3)
4. Создание `windows_correlation_rules.zip`

### Поэтапный запуск

#### Task 1: Нормализация событий
```bash
python process_correlations.py
```

Обрабатывает все `events_*.json` файлы и создает соответствующие `norm_fields_*.json`.

**Особенности реализации:**
- Все значения приводятся к lowercase (требование задания)
- Поддержка Sysmon, Security Log, PowerShell событий
- Автоматическое извлечение метаданных процессов
- Парсинг хешей (MD5, SHA1, SHA256, IMPHASH)

#### Tasks 2 & 3: Классификация и локализация
```bash
python classify_and_localize.py
```

Для каждой корреляции:
- Анализирует нормализованные события
- Определяет MITRE ATT&CK тактику и технику
- Генерирует `answers.json`
- Создает `i18n_en.yaml` и `i18n_ru.yaml`

**Используемые методы:**
- **RAG** - загрузка примеров из `macos_correlation_rules/` для контекста
- **Few-Shot Prompting** - примеры локализаций в промпте
- **Zero-Shot для классификации** - прямое определение MITRE по событиям

## Подход к решению

### Task 1: Нормализация

Создан класс `EventNormalizer`, который:
1. Парсит структуру Windows Event Log
2. Извлекает Provider, EventID, TimeCreated
3. Обрабатывает EventData с различными типами данных
4. Маппит на схему SIEM полей из `taxonomy_fields/`
5. Применяет lowercase ко всем значениям

**Примеры маппинга:**
- `System.TimeCreated.SystemTime` → `time`
- `System.Provider.Name` → `event_src.title`, `event_src.subsys`
- `EventData.Data[Name=User]` → `subject.account.domain`, `subject.account.name`
- `EventData.Data[Name=Image]` → `subject.process.fullpath`, `.path`, `.name`
- `EventData.Data[Name=Hashes]` → `subject.process.hash.md5`, `.sha1`, ...

### Task 2: MITRE ATT&CK Classification

Используется LLM (Claude 3.5 Sonnet или GPT-4) с промптом:

```
You are a cybersecurity expert specializing in MITRE ATT&CK framework.

Analyze the following normalized Windows security events and determine:
1. MITRE ATT&CK Tactic
2. MITRE ATT&CK Technique
3. Importance level (low, medium, or high)

Events:
[normalized fields]

Output format (JSON only):
{
  "tactic": "Tactic Name",
  "technique": "Technique Name",
  "importance": "high"
}
```

**Преимущества подхода:**
- Контекстное понимание событий
- Знание актуальной MITRE ATT&CK матрицы
- Правильное именование тактик/техник
- Автоматическое определение важности

### Task 3: Генерация локализаций

**RAG подход:**
1. Загружаются 3 примера из `macos_correlation_rules/`
2. Примеры включаются в промпт как few-shot examples
3. LLM генерирует локализации в том же стиле

**Промпт структура:**
```
Generate an English localization file (i18n_en.yaml) for a security correlation rule.

MITRE ATT&CK Classification:
- Tactic: [tactic]
- Technique: [technique]
- Importance: [importance]

Event Information:
[key normalized fields]

Example format:
[пример из macos_correlation_rules]

Generate with:
1. Description: Brief explanation
2. EventDescriptions: List with placeholders like {subject.account.name}
```

## Оценка результатов

### Task 1: Precision/Recall
- **TP (True Positive)**: поле и значение идентично эталону
- **FP (False Positive)**: поле отсутствует в эталоне или значение неверно
- **FN (False Negative)**: поле из эталона отсутствует в ответе

```
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
```

### Task 2: Accuracy
Accuracy по каждому полю (tactic, technique, importance) на всех корреляциях.

### Task 3: BERTScore
Семантическое сходство эмбеддингов между сгенерированными и эталонными локализациями.

## Результаты

После выполнения создается `windows_correlation_rules.zip` со структурой:

```
windows_correlation_rules/
├── correlation_1/
│   ├── i18n/
│   │   ├── i18n_en.yaml
│   │   └── i18n_ru.yaml
│   ├── tests/
│   │   ├── events_1_1.json
│   │   └── norm_fields_1_1.json
│   └── answers.json
├── correlation_2/
│   └── ...
...
└── correlation_54/
    └── ...
```

## Отправка результатов

```bash
# Добавить ZIP в репозиторий
git add windows_correlation_rules.zip

# Закоммитить
git commit -m "Add homework task 4 solution"

# Отправить в GitHub
git push origin main
```

Автогрейдер автоматически проверит:
- Наличие всех `norm_fields_*.json`
- Правильность `answers.json` (tactic, technique, importance)
- Качество локализаций через BERTScore

## Примечания

1. **Токены LLM**: Обработка ~54 корреляций потребует ~500-1000 запросов к API
2. **Стоимость**: Claude 3.5 Sonnet ~$0.50-1.00 за весь датасет
3. **Время**: ~30-60 минут полной обработки
4. **Альтернативы**: Можно использовать локальные модели через Ollama (Llama 3, Mistral)

## Локальные модели (опционально)

Для использования без API ключей:

```bash
# Установить Ollama
brew install ollama  # macOS
# или скачать с https://ollama.ai

# Запустить модель
ollama run llama3

# Изменить classify_and_localize.py:
# Заменить вызовы API на Ollama HTTP endpoint
```

## Troubleshooting

### Ошибка: "No API key configured"
- Установите переменную окружения `ANTHROPIC_API_KEY` или `OPENAI_API_KEY`

### Ошибка: Rate limit exceeded
- Добавьте `time.sleep(1)` между запросами в `classify_and_localize.py`

### Файл локализации невалидный YAML
- LLM иногда добавляет markdown блоки - скрипт автоматически их убирает
- При ошибках проверьте сгенерированный файл вручную

## Авторство

Решение создано для курса "Machine Learning in Information Security"

Использованные технологии:
- Python 3.13
- PyYAML для работы с таксономией
- Anthropic Claude 3.5 Sonnet для классификации и генерации
- OpenAI GPT-4 (альтернатива)

## Лицензия

Для образовательных целей.
