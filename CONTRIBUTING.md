# Contributing

## Install dependencies

Install development dependencies:

```bash
poetry install --with=dev
```

## (Optional) Re-generate query file

If the client is modified for a new verion's schema, run the code generator:

```bash
rm -r src/binaryai/client_stub && \
poetry run ariadne-codegen
```

## Formatter and linter

Recommend to run following commands

```sh
poetry run flake8 . && \
poetry run black --line-length=120 . && \
poetry run isort --profile=black --line-length=120 .
```
