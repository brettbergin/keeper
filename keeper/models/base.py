"""Base model class with common fields and methods."""

from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict

from flask import current_app
from sqlalchemy import Column, DateTime, Integer
from sqlalchemy.exc import SQLAlchemyError

from .database import db


class BaseModel(db.Model):
    """Base model class with common fields."""

    __abstract__ = True

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert model instance to dictionary."""
        return {
            column.name: getattr(self, column.name) for column in self.__table__.columns
        }

    def update(self, **kwargs) -> None:
        """Update model instance with provided keyword arguments."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at = datetime.utcnow()

    def save(self) -> None:
        """Save model instance to database."""
        db.session.add(self)
        db.session.commit()

    def delete(self) -> None:
        """Delete model instance from database."""
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def create(cls, **kwargs):
        """Create and save a new instance."""
        instance = cls(**kwargs)
        instance.save()
        return instance

    def save_safely(self) -> bool:
        """Save model instance with transaction safety."""
        try:
            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            current_app.logger.error(
                f"Database error saving {self.__class__.__name__}: {str(e)}"
            )
            db.session.rollback()
            return False
        except Exception as e:
            current_app.logger.error(
                f"Unexpected error saving {self.__class__.__name__}: {str(e)}"
            )
            db.session.rollback()
            return False

    def delete_safely(self) -> bool:
        """Delete model instance with transaction safety."""
        try:
            db.session.delete(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            current_app.logger.error(
                f"Database error deleting {self.__class__.__name__}: {str(e)}"
            )
            db.session.rollback()
            return False
        except Exception as e:
            current_app.logger.error(
                f"Unexpected error deleting {self.__class__.__name__}: {str(e)}"
            )
            db.session.rollback()
            return False

    @staticmethod
    @contextmanager
    def safe_transaction():
        """Context manager for safe database transactions."""
        from .database import db

        try:
            yield db.session
            db.session.commit()
        except SQLAlchemyError as e:
            current_app.logger.error(f"Database transaction error: {str(e)}")
            db.session.rollback()
            raise
        except Exception as e:
            current_app.logger.error(f"Unexpected transaction error: {str(e)}")
            db.session.rollback()
            raise
