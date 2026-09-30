"""Serial bridge (S13): the Host side of docs/19 methods 1-15. `Bridge` is the outbox consumer, the
inbox producer and the reconciler; wire helpers and evidence mapping live next to it."""

from .bridge import Bridge

__all__ = ["Bridge"]
