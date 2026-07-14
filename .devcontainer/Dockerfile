FROM mcr.microsoft.com/devcontainers/base:ubuntu24.04

USER vscode

# Install GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg && \
    sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null

# Install deps
RUN sudo apt update && \
    sudo apt install -y graphviz gh && \
    sudo rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
RUN rm -f ./install.sh
ENV PATH="$PATH:/home/vscode/.local/bin"

# Install Python versions using uv
RUN uv tool install tox --with tox-uv
RUN uv python install 3.9 3.10 3.11 3.12 3.13 3.14 3.14t
RUN uv python install pypy3
