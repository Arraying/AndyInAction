import asyncio
import discord
import json
import re
import logging
import dns.resolver
import requests
import requests.adapters
import urllib.parse

from andy import suite

# Use basic logging setup.
# Set all logging levels to INFO.
logging.basicConfig(level=logging.INFO)
logger_discord = logging.getLogger("discord")
logger_discord.setLevel(logging.INFO)

# Create locks for shared resources.
ban_cache_lock = asyncio.Lock()  # used for "client.ban_cache"
officer_lock = asyncio.Lock()  # used for "activate_officer" function

# We just need guild updates (to see channels and whatnot) and messages.
intents = discord.Intents(guilds=True, messages=True)

# Minimal Discord client.
client = discord.Client(
    activity=discord.Game("for fraud", type=discord.ActivityType.watching),
    intents=intents,
    guild_subscriptions=False,
    member_cache_flags=discord.MemberCacheFlags().none()
)
client.ban_cache = set()

# Create a DNS resolver.
dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = 0.2
dns_resolver.lifetime = 0.2

# Create the HTTP client to check for redirects.
http_session = requests.Session()
http_adapter = requests.adapters.HTTPAdapter(max_retries=0)
http_session.mount("http://", http_adapter)
http_session.mount("https://", http_adapter)

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
    # Ignore messages from webhooks
    if not isinstance(message.author, discord.Member):
        return
    # Ignore members with safe roles.
    for role in message.author.roles:
        if role.id in bot["safe_roles"]:
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
        # Ignore URLs without a HTTP(s) scheme.
        # Andy does not work well with not 100% valid URLs.
        if "http" not in url_raw:
            continue

        logging.info(f"Checking {url_raw}")
        # Extract the actual URL from potential redirects.
        actual_url = extract_actual_url(url_raw)
        parsed = urllib.parse.urlparse(actual_url)
        if suite.is_scam(config, parsed, validate_config=False):
            scam = True
            instance = actual_url
            logging.info(f"---> Detected scam!")
            break

    # If there has been a scam, deal with it.
    if scam:
        async with officer_lock:
            ban_success = await activate_officer(message, instance)
        if ban_success:
            await asyncio.sleep(60)
            async with ban_cache_lock:
                client.ban_cache.remove(message.author.id)
            logging.debug(f"User {message.author.id} removed from ban cache.")


async def activate_officer(message, instance):
    """
    Notify a channel, and if enabled, ban the message author.
    :param message: The created message.
    :param instance: The scam link found in the message's contents.
    """
    # Check if user has already been banned.
    async with ban_cache_lock:
        if message.author.id in client.ban_cache:
            return False

    # Look up the channel to notify.
    channel = client.get_channel(int(bot["channel"]))
    if channel is None:
        logging.error("Could not log as channel is invalid.")
        return False

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
            async with ban_cache_lock:
                client.ban_cache.add(message.author.id)
            return True
        except (discord.HTTPException, discord.Forbidden):
            logging.error(f"Banning {user_id} was not successful")
    return False


def extract_actual_url(sent_url):
    """
    Attempts to extract the actual in the case that some URLs are hidden behind a HTTP redirect.
    First it tries to resolve the DNS record, if this fails it will return the original URL automatically.
    The way this works is by sending a HEAD request to the server. This should return the real location if this is a redirect.
    The request is given a timeout so that requests to slow and/or dead sites don't hang up the program.
    :param sent_url: The URL to probe.
    :return: The underlying URL if this is a redirect, otherwise the inputted URL.
    """
    if not dns_exists(sent_url):
        return sent_url
    try:
        logging.info(f"---> Resolving redirect URL {sent_url}")
        response = http_session.head(sent_url)
        if response.is_redirect:
            return response.headers["location"]
        return sent_url
    except (requests.exceptions.Timeout, requests.exceptions.RetryError, requests.exceptions.SSLError):
        logging.info(f"---> Redirect check for {sent_url} experienced timeout")
        return sent_url


def dns_exists(sent_url):
    """
    Checks if a DNS record for the domain exists.
    This significantly increases the performance of the redirect checks.
    :param sent_url: The sent URL.
    :return: True if it exists, false otherwise.
    """
    domain = urllib.parse.urlparse(sent_url).netloc
    try:
        dns_resolver.resolve(domain)
        return True
    except (dns.exception.Timeout,
            dns.resolver.NXDOMAIN,
            dns.resolver.YXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers):
        return None


# Run the bot.
client.run(bot["token"])
