from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


def quiz_keyboard(q_index: int, options: list[str]) -> InlineKeyboardMarkup:
    labels = ["A", "B", "C", "D", "E"]
    buttons = []
    for i, _ in enumerate(options):
        label = labels[i] if i < len(labels) else str(i + 1)
        buttons.append(
            [InlineKeyboardButton(text=label, callback_data=f"quiz:{q_index}:{i}")]
        )
    return InlineKeyboardMarkup(inline_keyboard=buttons)
