FROM mcr.microsoft.com/devcontainers/python:1-3.9-bullseye

# Replace pypi source to tencent source
RUN apt update && apt install -yy pandoc

# Add devcontainer user
RUN groupdel users ; useradd -mUs /bin/bash devcontainer
USER devcontainer

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LANGUAGE=C.UTF-8
