from typing import Iterable, List

from models.project_model import Project
from schemas.project_schema import ProjectResponse


def map_to_project_response(project: Project) -> ProjectResponse:
    return ProjectResponse.model_validate(project)


def map_list_to_responses(projects: Iterable[Project]) -> List[ProjectResponse]:
    return [map_to_project_response(p) for p in projects]
