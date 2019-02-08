# Mailgun API Fuzzer

This is an executable specification file. This file follows markdown syntax.
Every heading in this file denotes a scenario. Every bulleted point denotes a step.

To execute this specification, run

    gauge run specs mailgun_api_fuzz.spec

## Mailgun API Email Fuzz

* Authenticate against restful API with key "<INSERT API TOKEN>" at endpoint "<YOUR MAILGUN URL>/messages" then fuzz endpoint with 100 requests starting with seed "<INSERT AN EMAIL ADDRESS HERE>".
