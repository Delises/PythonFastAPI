from fastapi import APIRouter
import os
import json
import datetime

router = APIRouter(tags=["Get info"])
cve_file = os.environ.get("CVE_FILE")
with open(cve_file, 'r') as file:
    data = json.load(file)

@router.get("/info")
def about_me():
    inf = {
        "App": "NIST API tool",
        "Description": "This api tool developed to make NIST database requests easier",
        "Company Name": "FlawlessCat",
        "Developers": "Maksym Mospanko",
        "Contact emails": {
            "Personal": "dlisol.sing@gmail.com",
            "Work": "maksym.mospanko.kb.2021@lpnu.ua"
        }
    }
    return inf
@router.get("/get/all")
def get_all_cve():
    try:
        current_date = datetime.datetime.today()
        previous_date = current_date - datetime.timedelta(days=5)
        cve = data["vulnerabilities"]
        response = []
        for c in cve:
            date = c.get("dateAdded")
            if previous_date.date() <= datetime.datetime.strptime(date, "%Y-%m-%d").date() <= current_date.date():
                response.append(c)
        if len(response) > 40:
            response = response[:40]
        return response
    except Exception as e:
        return {"Error in get_all_cve:": {e}}

@router.get("/get")
def get_cve_by_key(query: str):
    try:
        response = []
        for cve in data["vulnerabilities"]:
            for key, value in cve.items():
                if isinstance(value, str) and query.lower() in value.lower():
                    response.append(cve)
                    break
        return response
    except Exception as e:
        return {"Error in get_cve_by_key:": {e}}

@router.get("/get/new")
def get_new_cve():
    try:
        sorted_by_date = sorted(
            data["vulnerabilities"],
            key=lambda x: datetime.datetime.strptime(x["dateAdded"], "%Y-%m-%d"),
            reverse=True
        )
        return sorted_by_date[:10]
    except Exception as e:
        return {"Error in get_new_cve:": {e}}

@router.get("/get/known")
def get_known():
    try:
        response = []
        for cve in data["vulnerabilities"]:
            if cve["knownRansomwareCampaignUse"].lower() == "known":
                response.append(cve)
        return response[:10]
    except Exception as e:
        return {"Error in get_known:": {e}}
