from fastapi import Body, FastAPI, Query, Path
from typing import Annotated
from pydantic import BaseModel, Field

app = FastAPI(title="CVE API", description="API that handles CRUD operations for CVE vulnerabilities.")

CVEPATTERN : str = '^CVE-\d{4}-\d{4,7}$'

class Vulnerability(BaseModel):
    """Model for vulnerabilities"""
    title:       str        = Field(max_length=30, title='Title')
    cve:         str | None = Field(default = "", pattern=CVEPATTERN, title='Cve')
    criticality: int        = Field(ge=0,le=10, title='Criticality')
    description: str | None = Field(default = "", max_length=100, title='Description')
    
class Vulnerabilities_FilterParams(BaseModel):
    """Model for filtering vulnerabilities"""
    model_config = {"extra": "forbid"}
    min: int | None = Field(default=None,ge=0, le=10)
    max: int | None = Field(default=None,ge=0, le=10)
    title: str | None = Field(default=None)


@app.get("/vulnerability")
async def get_all_vulnerabilities(filter_query: Annotated[Vulnerabilities_FilterParams, Query()]):
    """
    Retrieves all vulnerabilities if no filter is applied, otherwise uses the following filters:
    Filters:
    - 'Title': Title of CVE contains.
    - 'Max/Min': Values of criticity in between.
    Potential status codes: `400, 404, 500`.
    """
    
    return {"message": "Hello World"}


@app.get("/vulnerability/{cve}")
async def get_vulnerability(cve : Annotated[str, Path(pattern=CVEPATTERN, title='Cve')]):
    """
    Returns the vulnerability by CVE
    Potential status codes: `400, 404, 500`.
    """
    
    return {"message": "Hello World"}


@app.post("/vulnerability")
async def post_vulnerability(vulnerability : Annotated[Vulnerability, Body()]):
    """
    Creates a new vulnerability object.
    Potential status codes: `400, 404, 500`.
    """
    return vulnerability


@app.delete("/vulnerability/{cve}")
async def delete_vulnerability(cve : Annotated[str, Path(pattern=CVEPATTERN, title='Cve')]):
    """
    Removes the specific vulnerability.
    Returns the removed vulnerability.
    Potential status codes: `400, 404, 500`.
    """
    return {"message": "Hello World"}