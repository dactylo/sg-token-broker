"""Allow `python -m sg_token_broker`."""

import sys

from sg_token_broker._cli import main

if __name__ == '__main__':
    sys.exit(main())
