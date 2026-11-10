"""SQLAlchemy ORM models for storing audit sessions, findings, scores, and report metadata."""
from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class AuditSessionModel(Base):
    """Stores high-level audit session summary, scores, and full JSON snapshot."""

    __tablename__ = "audit_sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    audit_id = Column(String(64), unique=True, index=True, nullable=False)
    status = Column(String(32), default="COMPLETED", nullable=False)
    started_at = Column(String(64), nullable=False)
    completed_at = Column(String(64), nullable=False)
    duration_seconds = Column(Float, default=0.0)

    # Host metadata
    hostname = Column(String(128), nullable=False)
    os_name = Column(String(128), nullable=False)
    os_build = Column(String(64), nullable=False)
    current_user = Column(String(128), nullable=False)
    is_admin = Column(Boolean, default=False)

    # Score & check statistics
    overall_score = Column(Float, nullable=False)
    risk_rating = Column(String(128), nullable=False)
    executive_summary = Column(Text, nullable=False)
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    warning_checks = Column(Integer, default=0)
    not_assessed_checks = Column(Integer, default=0)

    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Complete serialized FullAuditResultSchema JSON for instant rich retrieval
    full_result_json = Column(Text, nullable=False)

    findings = relationship(
        "AuditFindingModel",
        back_populates="session",
        cascade="all, delete-orphan",
    )
    category_scores = relationship(
        "CategoryScoreModel",
        back_populates="session",
        cascade="all, delete-orphan",
    )
    reports = relationship(
        "ReportMetadataModel",
        back_populates="session",
        cascade="all, delete-orphan",
    )


class AuditFindingModel(Base):
    """Stores individual security check findings for an audit session."""

    __tablename__ = "audit_findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    audit_id = Column(
        String(64),
        ForeignKey("audit_sessions.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    check_id = Column(String(32), index=True, nullable=False)
    category = Column(String(64), index=True, nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(32), index=True, nullable=False)
    severity = Column(String(32), index=True, nullable=False)
    finding_type = Column(String(64), nullable=False)
    evidence = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)

    session = relationship("AuditSessionModel", back_populates="findings")


class CategoryScoreModel(Base):
    """Stores category-level security score breakdown for an audit session."""

    __tablename__ = "category_scores"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    audit_id = Column(
        String(64),
        ForeignKey("audit_sessions.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    category = Column(String(64), nullable=False)
    category_label = Column(String(128), nullable=False)
    max_points = Column(Float, nullable=False)
    earned_points = Column(Float, nullable=False)
    percentage = Column(Float, nullable=False)
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    warning_checks = Column(Integer, default=0)
    not_assessed_checks = Column(Integer, default=0)

    session = relationship("AuditSessionModel", back_populates="category_scores")


class ReportMetadataModel(Base):
    """Stores metadata for generated PDF and JSON audit reports."""

    __tablename__ = "report_metadata"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    report_id = Column(String(64), unique=True, index=True, nullable=False)
    audit_id = Column(
        String(64),
        ForeignKey("audit_sessions.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    report_type = Column(String(16), nullable=False)  # "PDF" or "JSON"
    title = Column(String(256), nullable=False)
    hostname = Column(String(128), nullable=False)
    overall_score = Column(Float, nullable=False)
    file_name = Column(String(256), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(Integer, default=0)
    created_at = Column(String(64), nullable=False)

    session = relationship("AuditSessionModel", back_populates="reports")
