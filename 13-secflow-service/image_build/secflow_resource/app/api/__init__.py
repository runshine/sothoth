"""API router configuration."""

from fastapi import APIRouter
from app.api.resources import router as resource_router

api_router = APIRouter()

api_router.include_router(resource_router)