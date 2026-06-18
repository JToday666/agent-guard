from dataclasses import dataclass

@dataclass
class FineTuneJob:
    model_name: str
    dataset_name: str
    epochs: int = 3

def describe_job(job: FineTuneJob) -> str:
    return f'Fine-tuning {job.model_name} on {job.dataset_name} for {job.epochs} epochs'
