"""VDP demo — an elderly-user payment agent, and an agent trying to escape it.

    python -m demo.payment_agent    the authorized, well-behaved run
    python -m demo.hostile_agent    twelve attacks, all of which must fail

Nothing in this package is part of the trusted computing base. It imports every
layer and adds no enforcement of its own: if an attack were to succeed, the bug
would be in `policy`, `monitor`, `tokens`, or `runtime`, never here.

This module re-exports NOTHING on purpose. Importing a submodule here would put
it in `sys.modules` before `python -m demo.<name>` executes it, which runpy
warns about and which can run module-level code twice. Import the submodules
directly:

    from demo.payment_agent import authorize
    from demo.hostile_agent import run_attacks
"""
