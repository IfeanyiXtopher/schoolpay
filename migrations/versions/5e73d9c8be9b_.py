"""empty message

Revision ID: 5e73d9c8be9b
Revises: 
Create Date: 2023-10-16 11:59:48.228517

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5e73d9c8be9b'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('studentparent_link', schema=None) as batch_op:
        batch_op.create_foreign_key(None, 'parents', ['stdparentlink_parentsid'], ['parents_id'])
        batch_op.create_foreign_key(None, 'students', ['stdparentlink_stdid'], ['std_id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('studentparent_link', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_constraint(None, type_='foreignkey')

    # ### end Alembic commands ###
