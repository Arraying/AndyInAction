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
  "ban": true
}
```
The `token` represents the bot token, the `channel` is the ID of the channel where the bot will notify violations to. 
Setting `ban` to false will just log the violation, not ban for it.

Then, install all the requirements:
```
pip install -r requirements.txt
```

You can now run the bot as follows:  
**General:** `python bot.py`  
**Windows:** `py bot.py`