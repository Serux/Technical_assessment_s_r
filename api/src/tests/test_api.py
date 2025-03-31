from httpx import AsyncClient
import pytest

@pytest.mark.asyncio
async def test_create_vulnerability():
    test_item = {
      "title": "Vulnerability 11",
      "cve": "CVE-2023-6179",
      "criticality": 2,
      "description": "Description for vulnerability 11"
    }
    async with AsyncClient(base_url="http://api:8000") as client:
      response = await client.post("/vulnerability", json=test_item)
    assert response.status_code == 200
    assert response.json() == test_item
    
@pytest.mark.asyncio
async def test_create_vulnerability_missing_title():
    test_item = {
      
      "cve": "CVE-2023-6179",
      "criticality": 2,
      "description": "Description for vulnerability 11"
    }
    async with AsyncClient(base_url="http://api:8000") as client:
      response = await client.post("/vulnerability", json=test_item)
    assert response.status_code == 422

@pytest.mark.asyncio  
async def test_create_and_read_vulnerability():
    
    test_item = {
      "title": "Vulnerability 12",
      "cve": "CVE-2023-1234",
      "criticality": 6,
      "description": "Description for vulnerability 12"
    }
    async with AsyncClient(base_url="http://api:8000") as client:
      response1 = await client.post("/vulnerability", json=test_item)
    assert response1.status_code == 200
    assert response1.json() == test_item
    async with AsyncClient(base_url="http://api:8000") as client:
      response2 = await client.get("/vulnerability/CVE-2023-1234")
    assert response2.status_code == 200
    assert response2.json() == test_item