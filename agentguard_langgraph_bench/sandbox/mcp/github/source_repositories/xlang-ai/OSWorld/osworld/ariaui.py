class AriaUiRunner:
    def __init__(self, model_name: str = 'aria-ui-base'):
        self.model_name = model_name

    def supports_vllm(self) -> bool:
        return False
