from vantage.scanning.contracts import Scanner


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, Scanner] = {}

    def register(self, scanner: Scanner) -> None:
        if scanner.scanner_id in self._scanners:
            raise ValueError(f"Scanner already registered: {scanner.scanner_id}")
        self._scanners[scanner.scanner_id] = scanner

    def get(self, scanner_id: str) -> Scanner:
        try:
            return self._scanners[scanner_id]
        except KeyError as exc:
            raise LookupError(f"Unknown scanner: {scanner_id}") from exc

    def list(self) -> tuple[tuple[str, str, bool], ...]:
        return tuple(
            (s.scanner_id, s.display_name, s.supports_active_checks)
            for s in sorted(self._scanners.values(), key=lambda item: item.scanner_id)
        )
