# LinkGuard - Telegram-бот для проверки ссылок

![CI](https://github.com/k0mael3ctra/LinkGuardBot/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)

LinkGuard - практичный бот для анализа ссылок в Telegram. Он помогает быстро понять риск, объясняет причины и дает понятный отчет.
Бот работает в личных и групповых чатах и делает только оборонительные проверки.

## Статус

Версия: **0.1-beta**. Это учебный проект для себя: тренировка и разбор того, что мы навибкодили.
Следующие 2 дня упор будет на разбор всего, что тут есть: CI, структура, базы, как все работает,
чтобы я мог спокойно объяснить, как делал проект и что в нем “база”.

## 1) Что установить (самые простые шаги)

1. **Python 3.12+**
   - Скачай с сайта https://www.python.org/downloads/
   - Во время установки поставь галочку **Add Python to PATH**.
2. **Git** (нужен для GitHub)
   - https://git-scm.com/downloads
3. **VS Code**
   - https://code.visualstudio.com/

## 2) Создать Telegram-бота через BotFather

1. В Telegram найди бота **@BotFather**.
2. Напиши команду `/newbot`.
3. Введи имя и username бота.
4. BotFather пришлет токен. Это **секрет**, никому его не показывай.

## 3) Создать папку проекта и открыть в VS Code

1. Создай папку, например `D:\Projects\LinkGuardBot`.
2. Открой VS Code > **File > Open Folder** > выбери папку проекта.

## 4) Создать .venv и активировать (PowerShell и CMD)

**PowerShell:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**CMD:**
```bat
python -m venv .venv
.\.venv\Scripts\activate.bat
```

## 5) Создать .env и вставить BOT_TOKEN

Создай файл `.env` в корне проекта и добавь строку:
```
BOT_TOKEN=ТВОЙ_ТОКЕН_ОТ_BOTFATHER
```

Дополнительно (по желанию):
```
VT_API_KEY=...
GOOGLE_SAFE_BROWSING_API_KEY=...
URLSCAN_API_KEY=...
GROUP_MODE=quiet
```

- `GROUP_MODE`: режим для групп по умолчанию (`quiet` или `active`).
- Без ключей бот работает, но без внешних источников.

## 6) Установить зависимости

```powershell
pip install -r requirements.txt
```

## 7) Запуск бота

```powershell
python -m src.main
```

## 8) Проверка в Telegram

Напиши боту:
- `/start`
- `/check https://example.com`
- или просто отправь ссылку без команды, бот проверит сам (в личке)

## 9) Команды

- `/start` - старт и возможности
- `/help` - список команд
- `/check <url>` - анализ ссылки
- `/tips` - советы по безопасности
- `/about` - как работает проверка
- `/history` - последние проверки
- `/groupmode quiet|active` - режим группы
- `/quiz` - мини-викторина

## 10) Troubleshooting (частые ошибки)

- **requirements.txt not found**
  - Проверь, что ты в папке проекта.
- **python/pip not found**
  - Убедись, что Python добавлен в PATH и перезапусти терминал.
- **Execution Policy (PowerShell)**
  - Запусти PowerShell от имени пользователя и выполни:
    `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
- **invalid token**
  - Проверь, что токен правильный и без лишних пробелов.
- **module not found**
  - Убедись, что .venv активирован.

## 11) Как остановить бота

Нажми `Ctrl + C` в терминале.

## 12) (Опционально) запуск через Docker

```powershell
docker compose up --build
```

## 13) Как выложить на GitHub БЕЗ утечки токена

1. Файл `.env` уже в `.gitignore` - он не попадет в репозиторий.
2. Команды:
```powershell
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/USERNAME/REPO.git
git push -u origin main
```

## 14) Этика и безопасность

Этот проект **не делает вредоносных действий**. Он:
- не взламывает сайты
- не сканирует порты
- не выполняет SQLi/XSS
- не крадет данные
- не подделывает формы входа

## Источники и онлайн-анализ

Бот использует несколько источников и сервисов:
- URLhaus (malware ссылки)
- OpenPhish (фишинг)
- Google Safe Browsing (репутация)
- VirusTotal (мульти-движковая репутация)
- urlscan.io (онлайн-анализ, поведение и отчет)

Фиды кешируются локально в папке `data/feeds` и обновляются автоматически.

## Какие навыки ты получаешь и почему это ценится

- Создание Telegram-ботов на Python
- Асинхронные запросы и безопасные проверки
- Работа с конфигами и .env
- Тесты, линтер, CI
- Docker и запуск в проде

---

# Команды запуска

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m src.main
```

# Быстрый чеклист

- [ ] Python 3.12 установлен и добавлен в PATH
- [ ] В корне проекта есть `.env` с BOT_TOKEN
- [ ] .venv активирован
- [ ] Зависимости установлены
- [ ] Бот запускается и отвечает на /start
