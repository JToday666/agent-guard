class AriaUiVllmRunner:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def supports_vllm(self) -> bool:
        return True
