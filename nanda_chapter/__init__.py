"""nanda-chapter-kit — a chapter is the home network a personal agent joins.

The kit composes published primitives; it defines no protocol of its own:

* ``sm-org-server`` — the conformant wire floor (did:key TOFU registration,
  signed requests, trust ledger, ARP issuer log, A2UI surfaces, federation).
* ``sm-bridge``     — the AI Catalog + A2A card surfaces the NANDA Index resolves to.
* ``sm-oversight``  — M-of-N human quorum as signed ARP receipts (the council).
* ``sm-parc``       — portable reputation checked at admission.
* ``sm-dat``        — bounded delegated authority a council member hands its agent.
"""

import os as _os

# sm-org-server builds a module-level ``app`` when imported, and since 0.2.0 its
# default store is file-backed, so a bare import would drop ``sm-server.sqlite``
# into the current directory. The chapter always passes its own store; keep the
# import-time instance in memory. This runs before any submodule imports sm_server.
_os.environ.setdefault("SERVER_DB_PATH", ":memory:")

__version__ = "0.4.0"
