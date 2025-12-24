from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import BotCommand

from .bot.handlers import router
from .config import get_settings


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    settings = get_settings()
    bot = Bot(token=settings.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()
    dp.include_router(router)

    logging.info("LinkGuard bot started")
    await bot.set_my_commands(
        [
            BotCommand(command="start", description="Старт и возможности"),
            BotCommand(command="help", description="Список команд"),
            BotCommand(command="check", description="Проверка ссылки"),
            BotCommand(command="deepcheck", description="Углубленная проверка"),
            BotCommand(command="tips", description="Советы по безопасности"),
            BotCommand(command="about", description="Как работает проверка"),
            BotCommand(command="history", description="Последние проверки"),
            BotCommand(command="groupmode", description="Режим группы"),
            BotCommand(command="quiz", description="Мини-викторина"),
        ]
    )
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
