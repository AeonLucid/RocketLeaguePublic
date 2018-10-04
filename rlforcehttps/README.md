# RLForceHttps (Windows)

Rocket League automatically switches to a WebSocket connection.  
This is used to have it fallback to a normal HTTP api.

It takes around ~10 blocks to have it fallback to the HTTP api.

## Installation

1. Install `Python 2.7` or `Python 3.7`.
2. Run `pip install -r .\requirements.txt` in this directory.

## Run

1. Start RocketLeague.
2. Run `python main.py`.

Make sure to be fast, it should let you know if it has successfully blocked an attempt.  
If it doesn't, try again.
