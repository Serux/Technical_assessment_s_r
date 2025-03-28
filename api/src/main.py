from fastapi import Body, FastAPI, Query, Path
from typing import Annotated, Optional
from pydantic import BaseModel, Field, BeforeValidator
from pymongo import MongoClient, ASCENDING
from bson.json_util import dumps

app = FastAPI(title="CVE API", description="API that handles CRUD operations for CVE vulnerabilities.")

CVEPATTERN : str = '^CVE-\d{4}-\d{4,7}$'

class Vulnerability(BaseModel):
    """Model for vulnerabilities"""
    #id: Optional[Annotated[str, BeforeValidator(str)]] = Field(alias="_id", default=None)
    title:       str        = Field(max_length=30, title='Title')
    cve:         str | None = Field(default = "", pattern=CVEPATTERN, title='Cve')
    criticality: int        = Field(ge=0,le=10, title='Criticality')
    description: str | None = Field(default = "", max_length=100, title='Description')
class VulnerabilityCollection(BaseModel):
    """Model for list of vulnerabilities"""
    vulnerabilities: list[Vulnerability]
    
class Vulnerabilities_FilterParams(BaseModel):
    """Model for filtering vulnerabilities"""
    model_config = {"extra": "forbid"}
    min: int | None = Field(default=None,ge=0, le=10)
    max: int | None = Field(default=None,ge=0, le=10)
    title: str | None = Field(default=None)


@app.on_event("startup")
async def startup_db_client():
    client = MongoClient("mongodb://mongodb:27017/")
    app.mongodb = client["database"]
    
    # Ensure indexes
    app.mongodb.vulnerabilities.create_index([("cve", ASCENDING)], unique=True)


@app.get("/vulnerability")
async def get_all_vulnerabilities(filter_query: Annotated[Vulnerabilities_FilterParams, Query()]):
    """
    Retrieves all vulnerabilities if no filter is applied, otherwise uses the following filters:\n
    - 'Title': Title of CVE contains.\n
    - 'Max/Min': Values of criticity in between.\n
    Potential status codes: `400, 404, 500`.
    """
    
    return VulnerabilityCollection(vulnerabilities=app.mongodb.vulnerabilities.find().to_list())


@app.get("/vulnerability/{cve}")
async def get_vulnerability(cve : Annotated[str, Path(pattern=CVEPATTERN, title='Cve')]):
    """
    Returns the vulnerability by CVE.\n
    Potential status codes: `400, 404, 500`.
    """
    x : Vulnerability = app.mongodb.vulnerabilities.find_one( {'cve': cve},{'_id':0})
    return x


@app.post("/vulnerability")
async def post_vulnerability(vulnerability : Annotated[Vulnerability, Body()]):
    """
    Creates a new vulnerability object.\n
    Potential status codes: `400, 404, 500`.
    """
    myclient = MongoClient("mongodb://mongodb:27017/")
    mydb = myclient["database"]
    mycol = mydb["vulnerabilities"]
    
    mydict = vulnerability.model_dump(by_alias=True, exclude=["id"])

    x = app.mongodb.vulnerabilities.insert_one(mydict)
    
    return app.mongodb.vulnerabilities.find_one( {"_id": x.inserted_id})


@app.delete("/vulnerability/{cve}")
async def delete_vulnerability(cve : Annotated[str, Path(pattern=CVEPATTERN, title='Cve')]):
    """
    Removes the specific vulnerability.\n
    Returns the removed vulnerability.\n
    Potential status codes: `400, 404, 500`.
    """
    return {"message": "Hello World"}