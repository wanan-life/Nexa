from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.models.api_endpoint import APIEndpoint
from app.models.asset import Asset
from app.models.fingerprint import Fingerprint
from app.models.jsfile import JSFile
from app.models.risk import RiskFinding
from app.models.service import Service
from app.models.target import Target
from app.schemas.asset import AssetCreate
from app.schemas.service import ServiceCreate
from app.schemas.target import TargetCreate
from app.utils.normalize import normalize_host, normalize_url


def now_utc() -> datetime:
    return datetime.now(UTC)


class TargetRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, payload: TargetCreate) -> Target:
        name = normalize_host(payload.name)
        root_domain = normalize_host(payload.root_domain or name)
        existing = self.get_by_name(name)
        if existing:
            existing.root_domain = root_domain
            existing.program_name = payload.program_name
            existing.scope_type = payload.scope_type
            existing.updated_at = now_utc()
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        target = Target(
            name=name,
            root_domain=root_domain,
            program_name=payload.program_name,
            scope_type=payload.scope_type,
        )
        self.session.add(target)
        self.session.commit()
        self.session.refresh(target)
        return target

    def list(self) -> list[Target]:
        return list(self.session.exec(select(Target).order_by(Target.name)).all())

    def get(self, target_id: int) -> Target | None:
        return self.session.get(Target, target_id)

    def get_by_name(self, name: str) -> Target | None:
        normalized = normalize_host(name)
        statement = select(Target).where(Target.name == normalized)
        return self.session.exec(statement).first()

    def get_by_ref(self, ref: str) -> Target | None:
        if ref.isdigit():
            return self.get(int(ref))
        return self.get_by_name(ref)

    def delete_by_name(self, name: str) -> bool:
        target = self.get_by_name(name)
        if not target or target.id is None:
            return False
        assets = list(self.session.exec(select(Asset).where(Asset.target_id == target.id)).all())
        asset_ids = [asset.id for asset in assets if asset.id is not None]
        services: list[Service] = []
        if asset_ids:
            services = list(self.session.exec(select(Service).where(Service.asset_id.in_(asset_ids))).all())
        service_ids = [service.id for service in services if service.id is not None]

        if service_ids:
            for model in (APIEndpoint, Fingerprint, JSFile):
                rows = list(self.session.exec(select(model).where(model.service_id.in_(service_ids))).all())
                for row in rows:
                    self.session.delete(row)

        findings = list(
            self.session.exec(select(RiskFinding).where(RiskFinding.target_id == target.id)).all()
        )
        for finding in findings:
            self.session.delete(finding)
        for service in services:
            self.session.delete(service)
        for asset in assets:
            self.session.delete(asset)
        self.session.delete(target)
        self.session.commit()
        return True


class AssetRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(self, payload: AssetCreate) -> Asset:
        host = normalize_host(payload.host)
        existing = self.get_by_host(host)
        if existing:
            self._apply(existing, payload)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        asset = Asset(
            target_id=payload.target_id,
            host=host,
            asset_type=payload.asset_type,
            source=payload.source,
            ip=payload.ip,
            cname=payload.cname,
            is_alive=payload.is_alive,
        )
        self.session.add(asset)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.get_by_host(host)
            if not existing:
                raise
            self._apply(existing, payload)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing
        self.session.refresh(asset)
        return asset

    def list_by_target(self, target_id: int, alive_only: bool = False) -> list[Asset]:
        statement = select(Asset).where(Asset.target_id == target_id)
        if alive_only:
            statement = statement.where(Asset.is_alive == True)  # noqa: E712
        return list(self.session.exec(statement.order_by(Asset.host)).all())

    def get(self, asset_id: int) -> Asset | None:
        return self.session.get(Asset, asset_id)

    def get_by_host(self, host: str) -> Asset | None:
        normalized = normalize_host(host)
        statement = select(Asset).where(Asset.host == normalized)
        return self.session.exec(statement).first()

    def delete_by_host(self, host: str) -> bool:
        asset = self.get_by_host(host)
        if not asset:
            return False
        self.session.delete(asset)
        self.session.commit()
        return True

    @staticmethod
    def _merge_source(existing: str, incoming: str) -> str:
        values = [item.strip() for item in existing.split(",") if item.strip()]
        if incoming not in values:
            values.append(incoming)
        return ",".join(values)

    def _apply(self, asset: Asset, payload: AssetCreate) -> None:
        asset.target_id = payload.target_id
        asset.asset_type = payload.asset_type
        asset.source = self._merge_source(asset.source, payload.source)
        asset.ip = payload.ip or asset.ip
        asset.cname = payload.cname or asset.cname
        asset.is_alive = asset.is_alive or payload.is_alive
        asset.last_seen = now_utc()


class ServiceRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(self, payload: ServiceCreate) -> Service:
        url = normalize_url(payload.url)
        parsed = urlparse(url)
        scheme = payload.scheme or parsed.scheme
        port = payload.port or self._infer_port(parsed.scheme, parsed.port)
        existing = self.get_by_url(url)
        if existing:
            self._apply(existing, payload, url, scheme, port)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        service = Service(asset_id=payload.asset_id, url=url, scheme=scheme, port=port)
        self._apply(service, payload, url, scheme, port)
        self.session.add(service)
        self.session.commit()
        self.session.refresh(service)
        return service

    def list_by_target(self, target_id: int) -> list[Service]:
        statement = (
            select(Service)
            .join(Asset, Asset.id == Service.asset_id)
            .where(Asset.target_id == target_id)
            .order_by(Service.url)
        )
        return list(self.session.exec(statement).all())

    def list_by_asset(self, asset_id: int) -> list[Service]:
        statement = select(Service).where(Service.asset_id == asset_id).order_by(Service.url)
        return list(self.session.exec(statement).all())

    def get(self, service_id: int) -> Service | None:
        return self.session.get(Service, service_id)

    def get_by_url(self, url: str) -> Service | None:
        normalized = normalize_url(url)
        statement = select(Service).where(Service.url == normalized)
        return self.session.exec(statement).first()

    def delete(self, service_id: int) -> bool:
        service = self.get(service_id)
        if not service:
            return False
        self.session.delete(service)
        self.session.commit()
        return True

    def _apply(
        self,
        service: Service,
        payload: ServiceCreate,
        url: str,
        scheme: str,
        port: int | None,
    ) -> None:
        service.asset_id = payload.asset_id
        service.url = url
        service.scheme = scheme
        service.port = port
        service.status_code = payload.status_code
        service.title = payload.title
        service.content_length = payload.content_length
        service.favicon_hash = payload.favicon_hash
        service.server = payload.server
        service.cdn = payload.cdn
        service.waf = payload.waf
        service.technologies = payload.technologies
        service.response_headers = payload.response_headers
        service.screenshot_path = payload.screenshot_path
        service.last_checked_at = now_utc()

    @staticmethod
    def _infer_port(scheme: str, parsed_port: int | None) -> int | None:
        if parsed_port:
            return parsed_port
        if scheme == "http":
            return 80
        if scheme == "https":
            return 443
        return None
