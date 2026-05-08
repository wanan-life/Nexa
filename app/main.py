from fastapi import Depends, FastAPI, HTTPException, status
from sqlmodel import Session

from app.database import get_session, init_db
from app.repositories import AssetRepository, ServiceRepository, TargetRepository
from app.schemas.asset import AssetCreate, AssetRead
from app.schemas.service import ServiceCreate, ServiceRead
from app.schemas.target import TargetCreate, TargetRead

app = FastAPI(
    title="Nexa",
    version="0.1.0",
    description="Attack surface intelligence platform for authorized bug bounty workflows.",
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/targets", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def create_target(payload: TargetCreate, session: Session = Depends(get_session)):
    return TargetRepository(session).create(payload)


@app.get("/targets", response_model=list[TargetRead])
def list_targets(session: Session = Depends(get_session)):
    return TargetRepository(session).list()


@app.get("/targets/{name}", response_model=TargetRead)
def get_target(name: str, session: Session = Depends(get_session)):
    target = TargetRepository(session).get_by_name(name)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@app.delete("/targets/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(name: str, session: Session = Depends(get_session)):
    deleted = TargetRepository(session).delete_by_name(name)
    if not deleted:
        raise HTTPException(status_code=404, detail="target not found")


@app.post("/assets", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def upsert_asset(payload: AssetCreate, session: Session = Depends(get_session)):
    if not TargetRepository(session).get(payload.target_id):
        raise HTTPException(status_code=404, detail="target not found")
    return AssetRepository(session).upsert(payload)


@app.get("/targets/{name}/assets", response_model=list[AssetRead])
def list_assets(name: str, alive_only: bool = False, session: Session = Depends(get_session)):
    target = TargetRepository(session).get_by_name(name)
    if not target or target.id is None:
        raise HTTPException(status_code=404, detail="target not found")
    return AssetRepository(session).list_by_target(target.id, alive_only=alive_only)


@app.delete("/assets/{host}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(host: str, session: Session = Depends(get_session)):
    deleted = AssetRepository(session).delete_by_host(host)
    if not deleted:
        raise HTTPException(status_code=404, detail="asset not found")


@app.post("/services", response_model=ServiceRead, status_code=status.HTTP_201_CREATED)
def upsert_service(payload: ServiceCreate, session: Session = Depends(get_session)):
    if not AssetRepository(session).get(payload.asset_id):
        raise HTTPException(status_code=404, detail="asset not found")
    return ServiceRepository(session).upsert(payload)


@app.get("/targets/{name}/services", response_model=list[ServiceRead])
def list_services(name: str, session: Session = Depends(get_session)):
    target = TargetRepository(session).get_by_name(name)
    if not target or target.id is None:
        raise HTTPException(status_code=404, detail="target not found")
    return ServiceRepository(session).list_by_target(target.id)


@app.delete("/services/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_service(service_id: int, session: Session = Depends(get_session)):
    deleted = ServiceRepository(session).delete(service_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="service not found")

