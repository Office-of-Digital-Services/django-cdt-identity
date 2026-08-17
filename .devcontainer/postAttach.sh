#!/usr/bin/env bash
set -ux

# initialize pre-commit
pre-commit install --install-hooks --overwrite

# ensure the test Django app is setup
python manage.py migrate
python manage.py createsuperuser --no-input
