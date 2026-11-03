"""add onu_state time-series table (statistics page)

Revision ID: 7c4a91e0d3b8
Revises: 2037054bdc22
Create Date: 2026-11-03 06:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = '7c4a91e0d3b8'
down_revision = '2037054bdc22'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'onu_state',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('device_id', sa.String(length=10), nullable=False),
        sa.Column('interface', sa.String(length=50), nullable=False),
        sa.Column('mac', sa.String(length=50), nullable=True),
        sa.Column('is_online', sa.Boolean(), nullable=True),
        sa.Column('optical_power', sa.Float(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('dereg_reason', sa.String(length=50), nullable=True),
        sa.Column('recorded_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_charset='utf8mb4',
        mysql_engine='InnoDB'
    )
    op.create_index(op.f('ix_onu_state_device_id'), 'onu_state', ['device_id'], unique=False)
    op.create_index(op.f('ix_onu_state_interface'), 'onu_state', ['interface'], unique=False)
    op.create_index(op.f('ix_onu_state_recorded_at'), 'onu_state', ['recorded_at'], unique=False)
    op.create_index('idx_onu_state_lookup', 'onu_state', ['device_id', 'interface', 'recorded_at'], unique=False)
    op.create_index('idx_onu_state_time', 'onu_state', ['recorded_at'], unique=False)


def downgrade():
    op.drop_index('idx_onu_state_time', table_name='onu_state')
    op.drop_index('idx_onu_state_lookup', table_name='onu_state')
    op.drop_index(op.f('ix_onu_state_recorded_at'), table_name='onu_state')
    op.drop_index(op.f('ix_onu_state_interface'), table_name='onu_state')
    op.drop_index(op.f('ix_onu_state_device_id'), table_name='onu_state')
    op.drop_table('onu_state')
