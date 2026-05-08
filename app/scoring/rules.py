from dataclasses import dataclass


@dataclass(frozen=True)
class ScoreRule:
    rule_id: str
    title: str
    score: int
    recommendation: str


DEFAULT_RULES: list[ScoreRule] = [
    ScoreRule("keyword_env", "Environment keyword in hostname", 30, "Review exposed dev/test surface"),
    ScoreRule("swagger", "Swagger/OpenAPI exposed", 40, "Check API documentation authorization"),
    ScoreRule("graphql", "GraphQL endpoint exposed", 35, "Inspect GraphQL introspection and auth boundaries"),
    ScoreRule("sourcemap", "Source map found", 45, "Review source map contents for secrets and hidden APIs"),
    ScoreRule("http_500", "HTTP 500 or stack trace", 35, "Check error leakage and debug settings"),
    ScoreRule("admin_title", "Admin-like title", 25, "Review login and access control posture"),
    ScoreRule("direct_ip", "Likely direct origin exposure", 20, "Validate CDN bypass risk"),
    ScoreRule("actuator", "Spring Boot Actuator exposed", 50, "Check actuator endpoint authorization"),
    ScoreRule("loose_cors", "Loose CORS configuration", 25, "Validate CORS trust boundaries"),
    ScoreRule("js_secret", "Possible secret in JavaScript", 60, "Verify secret exposure and rotation need"),
    ScoreRule("internal_keyword", "Internal keyword found", 30, "Review internal-only asset exposure"),
]

