"""
RubyGuardian API Routes Package.

Contains FastAPI router definitions for all API endpoints:
  - classify: Classification of Ruby scripts
  - health: Service health and readiness checks
  - models: Model management and inspection
"""

from . import classify, health, models

__all__ = ["classify", "health", "models"]
