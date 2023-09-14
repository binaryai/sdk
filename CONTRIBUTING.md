# Contributing

## Formatter and linter

Recommend to run following commands

```sh
python3 -m pip install flake8==4.0.1 black==22.6.0 isort==5.10.1 && \
python3 -m flake8 . && \
python3 -m black --check --line-length=120 . && \
python3 -m isort --profile=black --line-length=120 -c .
```
