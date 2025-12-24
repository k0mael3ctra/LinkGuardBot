# LinkGuard - Telegram-бот для проверки ссылок

![CI](https://github.com/k0mael3ctra/LinkGuardBot/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)

LinkGuard - Telegram-бот для анализа ссылок. Проект ориентирован на практическую проверку URL и объяснение результатов.
Проверки выполняются только в оборонительном режиме.

## Статус

Версия: **0.1-beta**. Учебный проект для практики и аккуратной сборки базовой архитектуры.

## 1) Что установить

1. **Python 3.12+**
   - https://www.python.org/downloads/
2. **Git**
   - https://git-scm.com/downloads
3. **VS Code**
   - https://code.visualstudio.com/

## 2) Создать Telegram-бота через BotFather

1. В Telegram найти **@BotFather**.
2. Команда `/newbot`.
3. Имя и username бота.
4. Получить токен.

## 3) Открыть проект

1. Создать папку, например `D:\Projects\LinkGuardBot`.
2. Открыть в VS Code: **File > Open Folder**.

## 4) Виртуальное окружение

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

## 5) .env

Создать файл `.env` и добавить:
```
BOT_TOKEN=ТВОЙ_ТОКЕН_ОТ_BOTFATHER
```

Дополнительно:
```
VT_API_KEY=...
GOOGLE_SAFE_BROWSING_API_KEY=...
URLSCAN_API_KEY=...
GROUP_MODE=quiet
```

- `GROUP_MODE`: `quiet` или `active`.
- Без ключей бот работает, но без внешних источников.

## 6) Зависимости

```powershell
pip install -r requirements.txt
```

## 7) Запуск

```powershell
python -m src.main
```

## 8) Проверка

Написать боту:
- `/start`
- `/check https://example.com`
- или отправить ссылку без команды (в личке)

## 9) Команды

- `/start` - старт
- `/help` - список команд
- `/check <url>` - анализ
- `/deepcheck <url>` - углубленная проверка (urlscan.io)
- `/tips` - советы
- `/about` - как работает проверка
- `/history` - последние проверки
- `/groupmode quiet|active` - режим группы
- `/quiz` - мини-викторина

## 10) Troubleshooting

- **requirements.txt not found**: не та папка
- **python/pip not found**: Python не в PATH
- **Execution Policy (PowerShell)**: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
- **invalid token**: токен неверный
- **module not found**: .venv не активирован

## 11) Остановка

`Ctrl + C`

## 12) Docker (опционально)

```powershell
docker compose up --build
```

## 13) Публикация на GitHub

1. `.env` уже в `.gitignore`.
2. Команды:
```powershell
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/USERNAME/REPO.git
git push -u origin main
```

## 14) Этика

Проект не выполняет вредоносных действий.

## Источники и онлайн-анализ

Используются источники и сервисы:
- URLhaus (malware)
- Google Safe Browsing (репутация)
- VirusTotal (репутация)
- urlscan.io (онлайн-анализ)

Фид URLhaus кешируется локально в `data/feeds` и обновляется автоматически.
`urlscan.io` запускается при высоком риске или по команде `/deepcheck`.

---

## Быстрый чеклист

- [ ] Python 3.12 установлен
- [ ] .env с BOT_TOKEN создан
- [ ] .venv активирован
- [ ] зависимости установлены
- [ ] бот запускается и отвечает на /start
