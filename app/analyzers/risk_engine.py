from app.models.service import Service


def score_service(service: Service) -> tuple[int, list[str]]:
    """Placeholder risk scorer; real rules are implemented in the next phase."""

    _ = service
    return 0, []

