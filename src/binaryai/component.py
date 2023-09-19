class Component(object):
    """A component entity that represents a SCA result."""

    def __init__(
        self,
        name: str,
        version: str,
        description: str,
        summary: str,
        source_code_url: str,
    ) -> None:
        super().__init__()
        self.name = name
        self.version = version
        self.description = description
        self.summary = summary
        self.source_code_url = source_code_url
