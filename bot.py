import json
import re
import urllib.parse

import discord
from andy import suite

# We just need guild updates (to see channels and whatnot) and messages.
intents = discord.Intents(guilds=True, messages=True)

# Minimal Discord client.
client = discord.Client(
    activity=discord.Game("for fraud", type=discord.ActivityType.watching),
    intents=intents,
    guild_subscriptions=False,
    member_cache_flags=discord.MemberCacheFlags().none()
)
# URL regular expression precompiled for performance (from the internet).
url_pattern = re.compile(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))", re.DOTALL)

# Load and attempt to parse the config files.
config_file = open("config.json")
bot_file = open("bot.json")
config = json.load(config_file)
bot = json.load(bot_file)
suite.valid_config(config)


@client.event
async def on_ready():
    """
    Prints out when the bot is ready.
    """
    print("Andy awake and monitoring for fraud.")


@client.event
async def on_message(message):
    """
    When a message is received.
    This will scan the contents for URLs.
    For every URL, it will check if it is a scam URL.
    If so, it will notify a channel, and if enabled, ban the member.
    :param message: The created message.
    """

    # Ignore itself.
    if message.author == client.user:
        return

    # Check if the content has a URL.
    content = message.content
    matches_raw = url_pattern.findall(content)
    matches = ["".join(x) for x in matches_raw]

    # Pass each URL through Andy.
    scam = False
    instance = None
    for url_raw in matches:
        # Ignore empty matches
        if url_raw == "":
            continue

        print(f"Checking {url_raw}")
        parsed = urllib.parse.urlparse(url_raw)
        if suite.is_scam(config, parsed, validate_config=False):
            scam = True
            instance = url_raw
            print(f"---> Detected scam!")
            break

    # If there has been a scam, deal with it.
    if scam:
        # Look up the channel to notify.
        channel = client.get_channel(int(bot["channel"]))
        if channel is None:
            print("Could not log as channel is invalid.")
            return

        # Notify the channel with a rich embed
        link = f"[{instance}]({instance})"
        description = f"Automatically banned **{message.author.id}** for the following link. Please verify:\n{link}"
        embed = discord.Embed(description=description, colour=0xff0000)
        await channel.send(embed=embed)

        # If set up, ban the user.
        if bot["ban"]:
            await message.author.ban(reason="Fraud.")


# Run the bot
client.run(bot["token"])

# Clean up open files.
config_file.close()
bot_file.close()
