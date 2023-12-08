from typing import Dict

from fastapi import FastAPI

app = FastAPI()


@app.get("/{param}")
async def root(param: str) -> Dict[str, str]:
    return {"message": f"{param}"}
