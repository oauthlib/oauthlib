FROM mcr.microsoft.com/devcontainers/base:ubuntu24.04

USER vscode

# Install deps
RUN sudo apt update && \
    sudo apt install -y graphviz && \
    sudo rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
RUN rm -f ./install.sh
ENV PATH="$PATH:/home/vscode/.local/bin"

# Install Python versions using uv
RUN uv tool install tox --with tox-uv
RUN uv python install 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.14t
RUN uv python install pypy3
