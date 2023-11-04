from fastapi import Depends
from typing import Optional


class SampleDataService:

    def __init__(self):
        pass

    def get_version(self) -> str:
        return "1.0.0"


class SampleResource:

    def __init__(self, db=Depends(Optional[SampleDataService])):
        print(db)
        print (dir(db.dependency))
        print (db.dependency.get_version())

