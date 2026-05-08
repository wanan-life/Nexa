from app.scoring.rules import DEFAULT_RULES, ScoreRule


class ScoringEngine:
    def __init__(self, rules: list[ScoreRule] | None = None) -> None:
        self.rules = rules or DEFAULT_RULES

    def list_rules(self) -> list[ScoreRule]:
        return self.rules

