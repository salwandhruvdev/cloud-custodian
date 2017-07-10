import argparse
import json
import os
import logging

from c7n.credentials import SessionFactory
from c7n.policy import load as policy_load
from c7n import mu, resources


def main():
    from c7n.mu import LambdaManager
    from c7n.ufuncs.s3crypt import get_function



if __name__ == "__main__":
    main()