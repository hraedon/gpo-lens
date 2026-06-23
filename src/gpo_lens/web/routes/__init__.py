"""Route handlers for the gpo-lens web UI, split by surface.

Each module exports a ``register(app, templates)`` function that wires its
routes onto the FastAPI app.  ``create_app()`` calls each module's
``register()`` in turn.
"""
