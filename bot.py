import asyncio
import json
import re
import urllib.parse

import discord
from andy import suite

# Use basic logging setup.
# Set all logging levels to INFO.
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("discord")
logger.setLevel(logging.INFO)

# Shared resources that require locks.
class BanCache(set):
    """
    Set of users recently banned for fraud.
    Shared resource intended to be used via acquiring its lock:

    async with BanCache.lock:
        # use BanCache object
    """
    lock = asyncio.Lock()

class Officer:
    """
    Routine for notifying a channel and banning a user.
    Shared resource intended to be used via acquiring its lock:

    async with Officer.lock:
        # use Officer object
    """
    lock = asyncio.Lock()

    @staticmethod
    async def activate(message, instance):
        """
        Notify a channel, and if enabled, ban the message author.
        :param message: The created message.
        :param instance: The scam link found in the message's contents.
        """
        # Check if user has already been banned.
        async with client.ban_cache.lock:
            if message.author.id in client.ban_cache:
                logging.debug(f"User {message.author.id} found in ban cache.")
                return

        # Look up the channel to notify.
        channel = client.get_channel(int(bot["channel"]))
        if channel is None:
            logging.error("Could not log as channel is invalid.")
            return

        # Notify the channel with a rich embed.
        user_id = message.author.id
        link = f"[{instance}]({instance})"
        description = f"Automatically banned **{user_id}** ({message.author.name}#{message.author.discriminator}) for the following link. Please verify:\n{link}"
        embed = discord.Embed(description=description, colour=0xff0000)
        await channel.send(embed=embed)

        # If set up, ban the user.
        if bot["ban"]:
            # First, DM the user about the ban.
            dm = bot["dm"]
            if dm != "":
                # Attempt to send DM, if it fails, not the end of the world.
                try:
                    await message.author.send(dm)
                except (discord.HTTPException, discord.Forbidden):
                    logging.error(f"Private messaging {user_id} was not successful")

            # Attempt to ban.
            try:
                await message.author.ban(reason="Fraud.", delete_message_days=1)
                async with client.ban_cache.lock:
                    client.ban_cache.add(message.author.id)
                    logging.debug(f"User {message.author.id} cached.")
                return 1
            except (discord.HTTPException, discord.Forbidden) as e:
                logging.error(f"Banning {user_id} was not successful")


# We just need guild updates (to see channels and whatnot) and messages.
intents = discord.Intents(guilds=True, messages=True)

# Minimal Discord client.
client = discord.Client(
    activity=discord.Game("for fraud", type=discord.ActivityType.watching),
    intents=intents,
    guild_subscriptions=False,
    member_cache_flags=discord.MemberCacheFlags().none()
)
client.ban_cache = BanCache()
client.officer = Officer()

# URL regular expression precompiled for performance (from the internet).
url_pattern = re.compile(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))", re.DOTALL)

# Load and attempt to parse the config files.
with open("config.json") as config_file, open("bot.json") as bot_file:
    config = json.load(config_file)
    suite.valid_config(config)
    bot = json.load(bot_file)

@client.event
async def on_ready():
    """
    Print out when the bot is ready.
    """
    logging.info("Andy awake and monitoring for fraud.")


@client.event
async def on_message(message):
    """
    Scan the contents of the message for URLs.
    For every URL, check if it is a scam URL using Andy.
    If detected as scam, notify a channel, and if enabled, ban the member.
    :param message: The created message.
    """

    # Ignore itself.
    if message.author == client.user:
        return
    # Ignore members with safe roles.
    for role in message.author.roles:
        if role.id in bot["safe_roles"]:
            return

    # Check if the content has a URL.
    content = message.content.lower()
    matches_raw = url_pattern.findall(content)
    matches = ["".join(x) for x in matches_raw]

    # Pass each URL through Andy.
    scam = False
    instance = None
    for url_raw in matches:
        # Ignore empty matches
        if url_raw == "":
            continue
        # Ignore URLs without a HTTP(s) scheme.
        # Andy does not work well with not 100% valid URLs.
        if "http" not in url_raw:
            continue

        logging.info(f"Checking {url_raw}")
        parsed = urllib.parse.urlparse(url_raw)
        if suite.is_scam(config, parsed, validate_config=False):
            scam = True
            instance = url_raw
            logging.info(f"---> Detected scam!")
            break

    # If there has been a scam, deal with it.
    if scam:
        async with client.officer.lock:
            ban_success = await client.officer.activate(message, instance)
        if ban_success:
            await asyncio.sleep(60)
            async with client.ban_cache.lock:
                client.ban_cache.remove(message.author.id)
            logging.debug(f"User {message.author.id} removed from ban cache.")



# Run the bot.
client.run(bot["token"])
