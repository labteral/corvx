from ordered_set import OrderedSet
from typing import Any


class CircularOrderedSet(OrderedSet):
    def __init__(self, size: int = 0):
        super(CircularOrderedSet, self).__init__()
        self.size = size

    def add(self, value: Any) -> None:
        super(CircularOrderedSet, self).add(value)
        self._truncate()

    def _truncate(self) -> None:
        if len(self) > self.size:
            self.pop(last=False)
