from fastapi import Body, FastAPI, Query, Path, Request, status
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from typing import Annotated, Optional
from pydantic import BaseModel, Field, BeforeValidator
from pymongo import MongoClient, ASCENDING, errors
from bson.json_util import dumps
from os import environ

### CONSTANTS
CVE_PATTERN : str = '^CVE-\d{4}-\d{4,7}$'
RESPONSE_CODES = {
    400: {"description": "Bad Request"},
    404: {"description": "Item not Found"},
    500: {"description": "Server Error"},
}


### PYDANTIC MODELS 
class Vulnerability(BaseModel):
    """Model for vulnerabilities"""
    title:       str        = Field(max_length=30, title='Title')
    cve:         str | None = Field(default = "", pattern=CVE_PATTERN, title='Cve')
    criticality: int        = Field(ge=0,le=10, title='Criticality')
    description: str | None = Field(default = "", max_length=100, title='Description')
class VulnerabilityCollection(BaseModel):
    """Model for a list of vulnerabilities"""
    vulnerabilities: list[Vulnerability]
    
class Vulnerabilities_FilterParams(BaseModel):
    """Model for filtering vulnerabilities"""
    model_config = {"extra": "forbid"}
    min: int | None = Field(default=None,ge=0, le=10)
    max: int | None = Field(default=None,ge=0, le=10)
    title: str | None = Field(default=None)

### FASTAPI

app = FastAPI(title="CVE API", description="API that handles CRUD operations for CVE vulnerabilities.")

@app.on_event("startup")
async def startup_db_client():
    # MongoDB url defined by environment variable, with the url from docker-compose by default.
    client = MongoClient(environ.get("MONGO_URL", "mongodb://mongodb:27017/"))
    
    # For easier access to the database, adding it to app.
    app.mongodb = client["database"]
    
    # Ensures that indexes exists, if not creates them 
    # Index for filtering Cve and to be unique 
    app.mongodb.vulnerabilities.create_index([("cve", ASCENDING)], unique=True)
    # Index for filtering only by criticality
    app.mongodb.vulnerabilities.create_index([("criticality",ASCENDING)])
    # Index for the combined filter of title contains text and criticality
    app.mongodb.vulnerabilities.create_index([("title", "text",),("criticality",ASCENDING)])
    
    


@app.get("/vulnerability", responses=RESPONSE_CODES)
async def get_all_vulnerabilities(filter_query: Annotated[Vulnerabilities_FilterParams, Query()]):
    """
    Retrieves all vulnerabilities if no filter is applied, otherwise uses the following filters:\n
    - 'Title': Title of CVE contains provided text.\n
    - 'Max/Min': Values of criticality in between.\n
    Potential status codes: `400, 404, 500`.
    """
            
    query = {}
    if(filter_query.title!=None): 
        query |= { 'title': {'$regex': filter_query.title, '$options': 'i' }}
    if(filter_query.min!=None or filter_query.max!=None):
        query['criticality'] = {}
        if(filter_query.min!=None):
            query['criticality'] |= {'$gte': filter_query.min}
        if(filter_query.max!=None):
            query['criticality'] |= {'$lte': filter_query.max}
    
    return VulnerabilityCollection(vulnerabilities=app.mongodb.vulnerabilities.find(query).to_list())


@app.get("/vulnerability/{cve}", responses=RESPONSE_CODES)
async def get_vulnerability(cve : Annotated[str, Path(pattern=CVE_PATTERN, title='Cve')]):
    """
    Returns the vulnerability by CVE.\n
    Potential status codes: `400, 404, 500`.
    """
    try:
        item = app.mongodb.vulnerabilities.find_one( {'cve': cve},{'_id':0})
    except:
        raise HTTPException(status_code=500)
    if(item == None):
        return JSONResponse(status_code=404, content={"message": "Item not found"})
    return item


@app.post("/vulnerability", responses=RESPONSE_CODES)
async def post_vulnerability(vulnerability : Annotated[Vulnerability, Body()]):
    """
    Creates a new vulnerability object.\n
    Potential status codes: `400, 404, 500`.
    """
    
    vulnerability_dict = vulnerability.model_dump(by_alias=True)
    try:
        inserted_vuln = app.mongodb.vulnerabilities.insert_one(vulnerability_dict)
    except errors.DuplicateKeyError:
        return JSONResponse(status_code=400, content={"message": "Duplicated CVE : " + vulnerability.cve })
        
    except:
        raise HTTPException(status_code=500)
    
    try:
        db_inserted_vuln = app.mongodb.vulnerabilities.find_one( {"_id": inserted_vuln.inserted_id},{'_id':0})
    except:
        raise HTTPException(status_code=500)
    
    if(db_inserted_vuln == None):
        return JSONResponse(status_code=404, content={"message": "Item not found"})
    
    return db_inserted_vuln


@app.delete("/vulnerability/{cve}", responses=RESPONSE_CODES)
async def delete_vulnerability(cve : Annotated[str, Path(pattern=CVE_PATTERN, title='Cve')]):
    """
    Removes the specific vulnerability.\n
    Returns the removed vulnerability.\n
    Potential status codes: `400, 404, 500`.
    """
    try:
        delete_result = app.mongodb.vulnerabilities.find_one_and_delete({'cve': cve},{'_id':0})
    except:
        raise HTTPException(status_code=500)
    
    if(delete_result == None):
        return JSONResponse(status_code=404, content={"message": "Item not found"})
    return delete_result