"""WSGI entry point for Keeper application."""

import os
from keeper.app import create_app

# Create the Flask application instance
app = create_app()

if __name__ == "__main__":
    # For development only
    app.run(debug=True)