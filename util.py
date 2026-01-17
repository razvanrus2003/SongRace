from sqlalchemy import Column, Integer, String

class Lobby(Base):
    __tablename__ = 'lobbies'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    username = Column(String, nullable=False)

class SongInfo(Base):
    __tablename__ = 'songs'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    artist = Column(String, nullable=False)
