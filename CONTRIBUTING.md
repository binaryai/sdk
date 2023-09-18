# Contributing

## Formatter and linter

Recommend to run following commands

```sh
poetry install --with=dev && \
poetry run flake8 . && \
poetry run black --line-length=120 . && \
poetry run isort --profile=black --line-length=120 .
```
