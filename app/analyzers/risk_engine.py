from app.models.asset import Asset
from app.models.service import Service
from app.scoring.engine import RiskEvaluation, ScoringEngine


def score_service(asset: Asset, service: Service | None) -> RiskEvaluation:
    return ScoringEngine().evaluate(asset, service)

