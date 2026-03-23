# tg_bot.py (Telegram 守护进程模块)
import asyncio
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart

logger = logging.getLogger("tuck.tg_bot")

# 全局状态，供 proxy.py 动态修改
system_state = {"status": "idle", "task": ""}

dp = Dispatcher()

@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    await message.answer("🧠 Tuck 网关已启动。我是您的神经递质。")

@dp.message()
async def handle_user_message(message: types.Message):
    if system_state["status"] == "busy":
        # 忙碌时不打断原任务
        await message.answer(f"你好，当前正在执行：\n{system_state['task']}\n请稍后，执行完毕后回复您。")
    else:
        # 空闲时默认接待
        await message.answer("👀 眼睛(Router)已就绪，已记录您的需求，正在唤醒大脑(8B-R1)...")
        # TODO: 未来可在此处将 message.text 发送至 Helix-Mind 任务队列

async def start_telegram_daemon(token: str):
    """供 FastAPI Lifespan 调用的启动函数"""
    if not token:
        logger.warning("[Tuck] 未配置 TG_BOT_TOKEN，Telegram 守护进程未启动。")
        return
    try:
        bot = Bot(token=token)
        logger.info("[Tuck] Telegram Daemon starting...")
        await dp.start_polling(bot)
    except Exception as e:
        logger.error(f"[Tuck] Telegram Daemon 启动失败: {e}")
