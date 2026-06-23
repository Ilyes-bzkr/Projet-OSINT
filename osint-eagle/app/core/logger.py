"""
Configuration Loguru pour tout le projet.
Importer 'logger' depuis ce module dans tous les autres fichiers.
"""

import sys
from loguru import logger
from app.core.config import settings

# Supprimer le handler par défaut
logger.remove()

# Console : couleurs + format lisible
logger.add(
    sys.stdout,
    level=settings.log_level,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan> - <level>{message}</level>",
    colorize=True,
)

# Fichier : rotation quotidienne, rétention 7 jours
logger.add(
    settings.log_file,
    level="DEBUG",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    rotation="1 day",
    retention="7 days",
    encoding="utf-8",
)

__all__ = ["logger"]
