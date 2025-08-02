"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

This migration was generated automatically by Alembic.
Please review the generated SQL and modify if necessary.

Migration Details:
- Revision: ${up_revision}
- Previous: ${down_revision | comma,n}
- Created: ${create_date}
- Branch Labels: ${branch_labels | comma,n}
- Depends On: ${depends_on | comma,n}

IMPORTANT NOTES:
1. Review all generated SQL before applying in production
2. Test migrations on a copy of production data first
3. Consider downtime requirements and backup procedures
4. Verify that all constraints and indexes are appropriate
5. Check that encrypted fields are handled correctly
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: str = ${repr(up_revision)}
down_revision: Union[str, None] = ${repr(down_revision)}
branch_labels: Union[str, Sequence[str], None] = ${repr(branch_labels)}
depends_on: Union[str, Sequence[str], None] = ${repr(depends_on)}


def upgrade() -> None:
    """
    Apply the migration changes to upgrade the database schema.
    
    This function contains the SQL operations to move the database
    from the previous revision to this revision.
    
    Note:
        All operations should be idempotent where possible.
        Consider the impact on existing data and add appropriate
        data migration logic if needed.
    """
${upgrades if upgrades else "    pass"}


def downgrade() -> None:
    """
    Revert the migration changes to downgrade the database schema.
    
    This function contains the SQL operations to move the database
    from this revision back to the previous revision.
    
    WARNING:
        Downgrade operations may result in data loss.
        Ensure you have appropriate backups before running downgrades.
        Consider the implications of removing columns or tables.
    """
${downgrades if downgrades else "    pass"}