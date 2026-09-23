import logging
from typing import List

from exceptions import (
    ProjectAlreadyExistsError,
    ProjectNotFoundError,
    ValidationError,
)
from mappers.project_mapper import map_list_to_responses, map_to_project_response
from models.project_model import Project
from repositories.project_repository import ProjectRepository
from utils.events import publish_project_changed
from schemas.project_schema import (
    CreatedResponse,
    MessageResponse,
    ProjectCreate,
    ProjectResponse,
    ProjectUpdate,
)

logger = logging.getLogger(__name__)


class ProjectService:
    def __init__(self, repository: ProjectRepository):
        self.repo = repository

    async def create_project(self, data: ProjectCreate) -> CreatedResponse:
        logger.info("Creating project: '%s'", data.project_name)

        if await self.repo.exists_by_name(data.project_name):
            logger.warning("Duplicate project name: '%s'", data.project_name)
            raise ProjectAlreadyExistsError(data.project_name)

        project = Project(
            project_name=data.project_name,
            entities=list(data.entities or []),
            customized=[item.model_dump() for item in (data.customized or [])],
            redaction_type=data.redaction_type,
        )
        project = await self.repo.insert(project)
        logger.info("Project created: id=%s", project.id)
        return CreatedResponse(
            message="Project stored successfully",
            project_id=str(project.id),
        )

    async def get_all_projects(self) -> List[ProjectResponse]:
        projects = await self.repo.find_all()
        logger.info("Fetched %d projects", len(projects))
        return map_list_to_responses(projects)

    async def get_project(self, project_id: str) -> ProjectResponse:
        project = await self.repo.find_by_id(project_id)
        if project is None:
            raise ProjectNotFoundError(project_id)
        return map_to_project_response(project)

    async def update_project(self, project_id: str, data: ProjectUpdate) -> MessageResponse:
        project = await self.repo.find_by_id(project_id)
        if project is None:
            raise ProjectNotFoundError(project_id)

        if data.project_name and data.project_name != project.project_name:
            if await self.repo.exists_by_name(data.project_name):
                raise ProjectAlreadyExistsError(data.project_name)

        changes: dict = {}
        if data.project_name is not None:
            changes["project_name"] = data.project_name
        if data.entities is not None:
            changes["entities"] = list(data.entities)
        if data.customized is not None:
            changes["customized"] = [item.model_dump() for item in data.customized]
        if data.redaction_type is not None:
            changes["redaction_type"] = data.redaction_type

        merged_entities = changes.get("entities", project.entities or [])
        merged_customized = changes.get("customized", project.customized or [])
        if not merged_entities and not merged_customized:
            raise ValidationError("At least one of 'entities' or 'customized' must be non-empty")

        await self.repo.update(project, changes)
        await publish_project_changed(project_id)
        logger.info("Project updated: id=%s", project_id)
        return MessageResponse(message="Project updated successfully")

    async def delete_project(self, project_id: str) -> MessageResponse:
        project = await self.repo.find_by_id(project_id)
        if project is None:
            raise ProjectNotFoundError(project_id)
        await self.repo.delete(project)
        await publish_project_changed(project_id)
        logger.info("Project deleted: id=%s", project_id)
        return MessageResponse(message="Project deleted successfully")
