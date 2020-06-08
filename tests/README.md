# binaryai test

## requirement
python == 3.8
pandas, pytest, pytest-xdist

## usage

test function module
```shell
$ pytest -v -n auto test_function --url {API_URL} --token {TOKEN}
```

test command line
```shell
$ pytest -v -n auto test_cli --url {API_URL} --token {TOKEN}
```
