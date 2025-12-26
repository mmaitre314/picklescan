FROM mcr.microsoft.com/azurelinux/base/python:3.11

# Install Dev Container dependencies
RUN tdnf install -y git tar awk && tdnf clean all

# Remove root access
USER nonroot
WORKDIR /home/nonroot

# Install Python packages
# Create a virtual environment to avoid access-denied issues when running pip install
ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=/home/nonroot/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
COPY requirements.txt .
RUN python3 -m venv .venv && .venv/bin/pip install --disable-pip-version-check --no-cache-dir -r requirements.txt
