ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    USER=cdt

# create non-root $USER and home directory
RUN useradd --create-home --shell /bin/bash $USER && \
    mkdir /home/$USER/src && \
    chown $USER:$USER /home/$USER/src && \
# install dev components
    python -m pip install --upgrade pip

WORKDIR /home/$USER/src

# switch to non-root $USER
USER $USER

# update env for local pip installs
# see https://docs.python.org/3/using/cmdline.html#envvar-PYTHONUSERBASE
# since all `pip install` commands are in the context of $USER
# $PYTHONUSERBASE is the location used by default
ENV PATH="$PATH:/home/$USER/.local/bin" \
    PYTHONPATH="/home/$USER/src" \
    PYTHONUSERBASE="/home/$USER/.local"

COPY .git .git
COPY cdt_identity cdt_identity
COPY pyproject.toml pyproject.toml

# install devcontainer requirements
RUN pip install -e .[dev,test]

CMD ["sleep", "infinity"]
