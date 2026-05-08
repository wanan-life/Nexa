from app.models.service import Service


def summarize_http_service(service: Service) -> dict[str, object]:
    return {
        "url": service.url,
        "status_code": service.status_code,
        "title": service.title,
        "server": service.server,
        "cdn": service.cdn,
        "waf": service.waf,
    }

