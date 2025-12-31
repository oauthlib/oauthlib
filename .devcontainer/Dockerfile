FROM mcr.microsoft.com/devcontainers/base:ubuntu24.04

USER vscode

# Install deps
RUN sudo apt update && \
    sudo apt install -y graphviz

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="$PATH:/home/vscode/.local/bin"

# Install Python versions using uv
RUN uv tool install tox --with tox-uv
RUN uv python install 3.8 3.9 3.10 3.11 3.12 3.13
RUN uv python install pypy3
RUN uvx pip install ruff pre-commit
RUN uvx pre-commit install
