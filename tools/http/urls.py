"""One query merge contract for HTTP execution and credential-masked previews."""
import httpx


def effective_url(url: str, query: dict) -> httpx.URL:
    target = httpx.URL(url)
    return target.copy_merge_params(query) if query else target
