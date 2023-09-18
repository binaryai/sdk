import json
from typing import List


class LicenseTagItem(json.JSONDecoder):
    """A license tag item entity."""

    def __init__(self, tag_name: str, description: str) -> None:
        super().__init__()
        self.tag_name = tag_name
        self.description = description


class LicenseTags(json.JSONDecoder):
    """A license tag entity."""

    def __init__(
        self,
        permission: List[LicenseTagItem],
        condition: List[LicenseTagItem],
        forbidden: List[LicenseTagItem],
    ) -> None:
        super().__init__()
        self.permission = permission
        self.condition = condition
        self.forbidden = forbidden


class License(json.JSONDecoder):
    """A license entity."""

    def __init__(
        self,
        short_name: str,
        full_name: str,
        content: str,
        url: str,
        source: str,
        tags: LicenseTags = None,
        risk: str = None,
        extra: str = None,
        is_pass: bool = None,
        check_reason: str = None,
    ) -> None:
        super().__init__()
        self.full_name = full_name
        self.short_name = short_name
        self.content = content
        self.risk = risk
        self.tags = tags
        self.source = source
        self.url = url
        self.extra = extra
        self.is_pass = is_pass
        self.check_reason = check_reason
