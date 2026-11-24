"""Mode SDK broker, fence-read broker and mode readbacks of the promotion mode stages (P16b)."""


class ModeBroker:
    """Finite private SDK dispatcher of one mode seed/start operation, on its own derived mc-* session.

    The read session serves mode_readbacks and the unit outputs; any unknown native outcome poisons, never retries.
    """

    @property
    def uncertainty(self):
        return [item for ledger in self.evidence for item in ledger.uncertainty]


class FenceReadBroker:
    """Finite private dispatcher of the observe operations: strong FENCE/SEMAPHORE GetItem on the fence session only."""

    @property
    def uncertainty(self):
        return [item for ledger in self.evidence for item in ledger.uncertainty]
