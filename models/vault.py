from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from models import Base


class VaultEntry(Base):
    __tablename__ = 'vault_entries'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)

    # Encrypted fields
    encrypted_title = Column(String(255), nullable=False)
    encrypted_username = Column(String(255), nullable=True)
    encrypted_password = Column(String(512), nullable=False)
    encrypted_url = Column(String(512), nullable=True)
    encrypted_notes = Column(Text, nullable=True)

    # Initialization Vector / Nonce for AES-GCM (stored alongside the ciphertext)
    nonce_title = Column(String(24), nullable=False)
    nonce_username = Column(String(24), nullable=True)
    nonce_password = Column(String(24), nullable=False)
    nonce_url = Column(String(24), nullable=True)
    nonce_notes = Column(String(24), nullable=True)

    # Category & organization
    category = Column(String(50), default='login')  # login, card, note, identity
    is_favorite = Column(Boolean, default=False)
    last_used_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship('User', backref='vault_entries')

    def __repr__(self):
        return f"<VaultEntry {self.id} for User {self.user_id}>"
