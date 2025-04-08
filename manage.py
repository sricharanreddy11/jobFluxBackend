#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PARAM = 'ENV_PARAM'


def parse_argv(argv):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--env", required=True)
    return parser.parse_known_args(argv)


def fetch_env_from_argv(argv):
    args, argv = parse_argv(argv)
    if args.env in ['PROD', 'prod']:
        print('selecting .env_prod')
        os.environ.setdefault(ENV_PARAM, 'PROD')
    elif args.env in ['DEV', 'dev']:
        print('selecting .env_dev')
        os.environ.setdefault(ENV_PARAM, 'DEV')
    else:
        print('selecting .env_local')
        os.environ.setdefault(ENV_PARAM, 'LOCAL')
    return argv


def set_env(argv):
    """
    check in os environment first. if not available check from command argv
    """
    env = os.environ.get(ENV_PARAM)
    if env is None:
        argv = fetch_env_from_argv(argv)
    else:
        args, argv = parse_argv(argv)
    return argv



def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jobflux_backend.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    argv = set_env(sys.argv)

    execute_from_command_line(argv)


if __name__ == '__main__':
    main()
