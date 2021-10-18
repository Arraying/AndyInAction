# AndyInAction

Implementation of [Andy](https://github.com/Arraying/Andy) in order to monitor for fraud in Discord servers.
The bot will log a message to a channel and then ban (can be disabled) the user if it detects fraud.

## Installation, Configuration & Usage

First, clone the repository:
```
git clone git@github.com:Arraying/AndyInAction.git
```

Then, create a file called `config.json` and fill it out as specified [here](https://github.com/Arraying/Andy).

Next, create a file called `bot.json` and ensure it follows this template:
```json
{
  "token": "your_token_here",
  "channel": "your_channel_here",
  "safe_roles": [],
  "ban": true,
  "dm": "You have been banned from the server!"
}
```
The `token` represents the bot token, the `channel` is the ID of the channel where the bot will notify violations to.
`safe_roles` is a list of Discord role IDs - messages from server members with a safe role will not be checked for scam links.
Setting `ban` to false will just log the violation, not ban for it.
The `dm` value will be sent to the offender as a DM before banning.

Then, install all the requirements:
```
pip install -r requirements.txt
```

You can now run the bot as follows:  
**General:** `python bot.py`  
**Windows:** `py bot.py`
