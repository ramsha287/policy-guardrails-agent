import uuid
from typing import Optional, Sequence

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.project_model import Project


class ProjectRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def _to_uuid(project_id: str) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(project_id)
        except (ValueError, TypeError):
            return None

    async def find_by_id(self, project_id: str) -> Optional[Project]:
        pid = self._to_uuid(project_id)
        if pid is None:
            return None
        return await self.session.get(Project, pid)

    async def exists_by_name(self, name: str) -> bool:
        result = await self.session.execute(
            select(exists().where(Project.project_name == name))
        )
        return bool(result.scalar())

    async def find_all(self) -> Sequence[Project]:
        result = await self.session.execute(
            select(Project).order_by(Project.created_at.desc())
        )
        return result.scalars().all()

    async def insert(self, project: Project) -> Project:
        self.session.add(project)
        await self.session.commit()
        await self.session.refresh(project)
        return project

    async def update(self, project: Project, changes: dict) -> Project:
        for key, value in changes.items():
            setattr(project, key, value)
        await self.session.commit()
        await self.session.refresh(project)
        return project

    async def delete(self, project: Project) -> None:
        await self.session.delete(project)
        await self.session.commit()
