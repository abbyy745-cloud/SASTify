"""
Library Models Package

Contains models for external libraries that describe their taint behavior:
- Sources: Functions that return user-controlled data
- Sinks: Functions that are dangerous if passed tainted data
- Sanitizers: Functions that clean/neutralize tainted data
"""

from .flask_model import FlaskModel
from .django_model import DjangoModel
from .database_model import DatabaseModel
from .ai_model import AIModel
from .express_model import ExpressModel

# Convenience function to get all models
def get_all_models():
    return {
        'flask': FlaskModel(),
        'django': DjangoModel(),
        'database': DatabaseModel(),
        'ai': AIModel(),
        'express': ExpressModel(),
    }
