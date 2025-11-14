# Noverse Windows Configuration

This tool is based on my personal research on several topics, which I began documenting around July 2024. Initially, I uploaded them individually as messages on the [Discord server](https://discord.gg/E2ybG4j9jU), but the amount of different configurations became too large and hard to manage (and Discord isn't ideal for projects like this). If I used information from specific sources, I've included the links. Information gathered via binary string extraction, WPR, IDA, Procmon, etc. Default values from WinDbg, IDA, and stock installations. Minor mistakes or misinterpretations may exist, **corrections are welcome**.

It's based on the GitHub repository and parses it's information out of it. All [`App Tools`](https://github.com/5Noxi/app-tools)/[`Game Tools`](https://github.com/5Noxi/game-tools) are external PowerShell scripts, same goes for the [`Component Manager`](https://github.com/5Noxi/comp-mgr), [`Blocklist Manager`](https://github.com/5Noxi/blocklist-mgr) & [`Bitmask Calculator`](https://github.com/5Noxi/bitmask-calc).

## Licencing

This project is AGPL-3.0. You may copy, modify, and redistribute only if you comply with the AGPL: keep copyright and license notices, state your changes, provide the complete corresponding source (including build/installation info for user products), and license your derivative under AGPL-3.0. Any copying or redistribution outside these terms requires explicit permission. Closed-source redistribution of this code is not permitted.

## Misuse / Scam Warning

Many people repackage configs from projects like this, or from places full of misinformation, and sell them as "magic optimizers". Don't pay for such apps that hide their source and offer only vague toggles like "Optimize System Performance". It often sounds appealing to inexperienced people, but mostly contains nothing of value, as the creators are trying to make a lot of money rather than create something good.

Hint: Check what a seller shares for free, if their free content already looks low effort or shows a lack of understanding, you can safely assume their paid product won't be any better. And if they refuse to share anything for free at all, you should question what their actual goal is. This is just a warning.

## My Projects

You can find all of my other projects here:
> https://5noxi.github.io/projects.html  
> https://github.com/5Noxi

More miscellaneous uploads:
> https://discord.gg/E2ybG4j9jU

## Requirements

> https://www.python.org/downloads/release/python-3130/?featured_on=pythonbytes

```ps
pip install PySide6 mistune requests
```

## Contribution

If you've something useful that isn't available in the tool yet, you're welcome to create a pull request. Note the JSON structure and provide appropriate documentation for the option - see [contribution.md](/contribution.md) for JSON structure details.