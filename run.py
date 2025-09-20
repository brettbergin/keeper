#!/usr/bin/env python3
"""Development server runner for Keeper application."""

import os
from keeper.app import create_app

if __name__ == '__main__':
    app = create_app()
    app.run(
        host=os.environ.get('HOST', '127.0.0.1'),
        port=int(os.environ.get('PORT', 8989)),
        debug=True
    )