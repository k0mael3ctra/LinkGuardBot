from __future__ import annotations

import logging
import re
import time

from aiogram import F, Router
from aiogram.filters import Command, CommandObject
from aiogram.types import CallbackQuery, Message, FSInputFile

from ..config import get_settings
from ..education import get_quiz_question, tips_text
from ..risk_engine import analyze_url
from .analytics import format_metrics, get_metrics, log_event, write_metrics_csv
from .group_mode_store import get_mode, set_mode
from .history_store import add_item, get_items, HistoryItem
from .keyboards import quiz_keyboard

router = Router()
settings = get_settings()
ADMIN_ID = 1938158970

MAX_MESSAGE = 3500
MAX_AUTO_URLS = 3

URL_REGEX = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)
DOMAIN_REGEX = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?\b", re.IGNORECASE)
TRAILING_PUNCT = ".,;:!?)]}>'\""


def _split_text(text: str) -> list[str]:
    parts = []
    remaining = text
    while len(remaining) > MAX_MESSAGE:
        cut = remaining.rfind("\n\n", 0, MAX_MESSAGE)
        if cut == -1:
            cut = MAX_MESSAGE
        parts.append(remaining[:cut].strip())
        remaining = remaining[cut:].strip()
    if remaining:
        parts.append(remaining)
    return parts


def _risk_label(level: str) -> str:
    return {"LOW": "НИЗКИЙ", "MEDIUM": "СРЕДНИЙ", "HIGH": "ВЫСОКИЙ"}.get(level, level)


def _risk_emoji(level: str) -> str:
    return {"LOW": "\u2705", "MEDIUM": "\u26a0\ufe0f", "HIGH": "\U0001F6A8"}.get(level, "\u26a0\ufe0f")


def _interpretation(level: str) -> str:
    if level == "HIGH":
        return "Высокий риск: есть подтвержденные сигналы угрозы или совпадения в базах."
    if level == "MEDIUM":
        return "Средний риск: есть подозрительные признаки, нужна осторожность."
    return "Низкий риск: по текущим проверкам угроз не обнаружено."


def _format_report(report) -> str:
    header = f"{_risk_emoji(report.risk_level)} {_risk_label(report.risk_level)} ({report.risk_score}/100)"

    url_lines = [
        f"Нормализованный: {report.normalized_url}",
        f"Схема: {report.scheme}",
        f"Домен: {report.host}",
        f"Путь: {report.path}",
        f"Параметры: {report.query or '-'}",
    ]
    if report.display_host and report.display_host != report.host:
        url_lines.append(f"Домен (IDN): {report.display_host}")

    intel = "\n".join(f"- {item}" for item in report.intel)
    reasons = "\n".join(f"- {r}" for r in report.reasons)
    technical = "\n".join(f"- {t}" for t in report.technical)
    unavailable = ""
    if report.unavailable:
        unavailable = "Не удалось проверить\n" + "\n".join(f"- {item}" for item in report.unavailable) + "\n\n"
    how = "\n".join(
        [
            "- Структура URL",
            "- HTTP-заголовки",
            "- Безопасность запроса",
            "- Анализ контента страницы",
            "- Базы угроз (URLhaus)",
            "- Репутация (Google Safe Browsing / VirusTotal)",
            "- Онлайн-скан (urlscan.io при высоком риске или /deepcheck)",
        ]
    )
    interpretation = _interpretation(report.risk_level)

    return (
        f"{header}\n\n"
        f"Интерпретация\n{interpretation}\n\n"
        f"URL\n" + "\n".join(url_lines) + "\n\n"
        f"Источники\n{intel}\n\n"
        f"{unavailable}"
        f"Признаки риска\n{reasons}\n\n"
        f"Техническое\n{technical}\n\n"
        f"Как мы это проверили\n{how}"
    )


def _quiz_text(q_index: int, question: dict) -> str:
    labels = ["A", "B", "C", "D", "E"]
    options_lines = []
    for i, option in enumerate(question["options"]):
        label = labels[i] if i < len(labels) else str(i + 1)
        options_lines.append(f"{label}) {option}")
    return (
        f"Вопрос {q_index + 1}/5\n{question['question']}\n\n"
        f"Варианты:\n" + "\n".join(options_lines)
    )


def _clean_url(value: str) -> str:
    return value.strip().rstrip(TRAILING_PUNCT)


def _extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for match in URL_REGEX.findall(text):
        value = _clean_url(match)
        if value not in found:
            found.append(value)
    for match in DOMAIN_REGEX.findall(text):
        value = _clean_url(match)
        if any(value in full for full in found):
            continue
        if value not in found:
            found.append(value)
    return found


def _is_admin(user_id: int | None, chat_type: str) -> bool:
    return bool(user_id) and user_id == ADMIN_ID


async def _send_report(
    message: Message,
    raw_url: str,
    deepcheck: bool = False,
    event_type: str = "check",
) -> None:
    logging.info("Checking URL: %s", raw_url)
    try:
        report = await analyze_url(
            raw_url,
            settings.vt_api_key,
            settings.google_safe_browsing_api_key,
            settings.urlscan_api_key,
            deepcheck=deepcheck,
        )
    except Exception as exc:
        logging.exception("Check failed")
        log_event(message.from_user.id, f"{event_type}_error", message.chat.type)
        await message.answer(f"Не удалось проверить ссылку: {exc}")
        return

    log_event(message.from_user.id, event_type, message.chat.type)

    await add_item(
        message.from_user.id,
        HistoryItem(
            url=report.normalized_url,
            risk_level=report.risk_level,
            risk_score=report.risk_score,
            timestamp=time.time(),
        ),
    )

    text = _format_report(report)
    for part in _split_text(text):
        await message.answer(part)


@router.message(Command("start"))
async def cmd_start(message: Message) -> None:
    log_event(message.from_user.id, "start", message.chat.type)
    text = (
        "LinkGuard - бот для проверки ссылок в Telegram.\n"
        "Отправь ссылку или используй /check. В группах авто-проверка работает в режиме active (/groupmode).\n"
        "Проверки: эвристики URL, безопасный HTTP, защитные заголовки и репутация."
    )
    await message.answer(text)


@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    text = (
        "Команды:\n"
        "/start - кратко о боте\n"
        "/help - список команд\n"
        "/check URL - стандартная проверка\n"
        "/deepcheck URL - углубленная проверка (urlscan.io)\n"
        "/tips - советы по безопасности\n"
        "/about - как устроена проверка\n"
        "/history - последние проверки\n"
        "/groupmode quiet|active - режим группы\n"
        "/stats [csv] - статистика (владелец)\n"
        "/quiz - мини-викторина\n\n"
        "В личке можно просто отправлять ссылку.\n"
        "В группах авто-проверка работает только в режиме active."
    )
    await message.answer(text)


@router.message(Command("about"))
@router.message(Command("how_it_works"))
async def cmd_about(message: Message) -> None:
    text = (
        "Как работает LinkGuard:\n\n"
        "1) Структура URL.\n"
        "   Проверяем домен, поддомены, символ @, подозрительные параметры и сокращатели.\n"
        "   Это логический анализ, а не черный список.\n\n"
        "2) Безопасный HTTP.\n"
        "   Таймауты, лимит редиректов и блок приватных IP защищают самого бота.\n\n"
        "3) Заголовки безопасности.\n"
        "   HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.\n"
        "   Отсутствие заголовков не означает вирус, но повышает риск.\n\n"
        "4) Публичные источники и репутация.\n"
        "   URLhaus и репутационные сервисы (Google Safe Browsing, VirusTotal).\n"
        "   Совпадение в базе резко повышает риск.\n\n"
        "5) Контент-анализ.\n"
        "   Ищем формы, поля пароля, подозрительные действия и навязанные загрузки.\n\n"
        "6) Итоговая оценка.\n"
        "   Риск - это сумма сигналов и вероятностная оценка, а не вердикт."
    )
    await message.answer(text)


@router.message(Command("tips"))
async def cmd_tips(message: Message) -> None:
    await message.answer(tips_text())


@router.message(Command("history"))
async def cmd_history(message: Message) -> None:
    items = await get_items(message.from_user.id, limit=5)
    if not items:
        await message.answer("История пуста.")
        return
    lines = []
    for item in items:
        lines.append(f"{_risk_emoji(item.risk_level)} {item.risk_level} {item.risk_score}/100 - {item.url}")
    await message.answer("Последние проверки:\n" + "\n".join(lines))


@router.message(Command("groupmode"))
async def cmd_groupmode(message: Message, command: CommandObject) -> None:
    if message.chat.type == "private":
        await message.answer("Команда доступна только в группах.")
        return

    try:
        member = await message.bot.get_chat_member(message.chat.id, message.from_user.id)
        if member.status not in {"administrator", "creator"}:
            await message.answer("Нужны права администратора, чтобы менять режим группы.")
            return
    except Exception:
        await message.answer("Не удалось проверить права администратора.")
        return

    arg = (command.args or "").strip().lower()
    if not arg:
        current = await get_mode(message.chat.id) or settings.group_mode
        await message.answer(f"Текущий режим: {current}. Используй /groupmode quiet|active")
        return

    if arg not in {"quiet", "active"}:
        await message.answer("Допустимые значения: quiet, active")
        return

    await set_mode(message.chat.id, arg)
    await message.answer(f"Режим группы установлен: {arg}")


@router.message(Command("stats"))
async def cmd_stats(message: Message, command: CommandObject) -> None:
    if not _is_admin(message.from_user.id, message.chat.type):
        await message.answer("Нет доступа. Команда доступна только владельцу.")
        return

    metrics = get_metrics()
    await message.answer(format_metrics(metrics))

    args = (command.args or "").strip().lower()
    if args in {"csv", "file"}:
        path = write_metrics_csv(metrics)
        await message.answer_document(FSInputFile(path), caption="metrics.csv")


@router.message(Command("quiz"))
async def cmd_quiz(message: Message) -> None:
    question = get_quiz_question(0)
    if not question:
        await message.answer("Викторина временно недоступна.")
        return
    text = _quiz_text(0, question)
    await message.answer(text, reply_markup=quiz_keyboard(0, question["options"]))


@router.callback_query(F.data.startswith("quiz:"))
async def quiz_answer(callback: CallbackQuery) -> None:
    try:
        _, q_index_str, a_index_str = callback.data.split(":")
        q_index = int(q_index_str)
        a_index = int(a_index_str)
    except ValueError:
        await callback.answer("Некорректные данные.", show_alert=True)
        return

    question = get_quiz_question(q_index)
    if not question:
        await callback.answer("Вопрос не найден.", show_alert=True)
        return

    is_correct = a_index == question["correct"]
    status = "Верно!" if is_correct else "Неверно."
    explanation = question["explain"]

    await callback.message.answer(f"{status} {explanation}")
    await callback.answer()

    next_q = get_quiz_question(q_index + 1)
    if next_q:
        text = _quiz_text(q_index + 1, next_q)
        await callback.message.answer(text, reply_markup=quiz_keyboard(q_index + 1, next_q["options"]))
    else:
        await callback.message.answer("Викторина завершена! Если хочешь, напиши /quiz еще раз.")


@router.message(Command("check"))
async def cmd_check(message: Message, command: CommandObject) -> None:
    if not command.args:
        await message.answer("Использование: /check URL\nПример: /check https://example.com")
        return

    raw_url = command.args.strip()
    await _send_report(message, raw_url, event_type="check")


@router.message(Command("deepcheck"))
async def cmd_deepcheck(message: Message, command: CommandObject) -> None:
    if not command.args:
        await message.answer("Использование: /deepcheck URL\nПример: /deepcheck https://example.com")
        return

    raw_url = command.args.strip()
    await _send_report(message, raw_url, deepcheck=True, event_type="deepcheck")


@router.message(F.text)
async def auto_check(message: Message) -> None:
    if not message.text or message.text.startswith("/"):
        return

    if message.chat.type != "private":
        mode = await get_mode(message.chat.id) or settings.group_mode
        if mode != "active":
            return

    urls = _extract_urls(message.text)
    if not urls:
        return

    if len(urls) > MAX_AUTO_URLS:
        await message.answer("Нашел много ссылок, проверю первые три.")
    for raw_url in urls[:MAX_AUTO_URLS]:
        await _send_report(message, raw_url, event_type="auto_check")
