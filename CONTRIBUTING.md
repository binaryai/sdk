# Contributing

## Install dependencies

Install development dependencies:

```bash
poetry install --with=dev
```

If you also want to modify documents, install related documents:

```bash
poetry install --with=dev --with=docs
```

## (Optional) Re-generate query file

If the client is modified for a new verion's schema, run the code generator:

```bash
rm -r src/binaryai/client_stub && \
poetry run ariadne-codegen
```

## Document and translation generation

We use Sphinx for document generation. After modified texts, you should re-generate the LOCALE files:

```bash
cd docs/
make getpo
```

And you can modify `*.po` files. To have a preview:

```bash
make all
```

## Formatter and linter

Run following commands before commit:

```sh
poetry run flake8 . && \
poetry run black --line-length=120 . && \
poetry run isort --profile=black --line-length=120 .
```
