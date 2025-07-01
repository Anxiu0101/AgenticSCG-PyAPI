from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess, tempfile, os, json, shutil

app = FastAPI()

class CodeIn(BaseModel):
    code: str

@app.post("/api/v1/secure-scan/python")
async def secure_scan(body: CodeIn):
    if not body.code:
        raise HTTPException(status_code=400, detail="code is required")

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".py") as f:
        f.write(body.code)
        f.flush()
        result = subprocess.run(
            ["bandit", "-r", f.name, "-f", "json"],
            capture_output=True, text=True, check=False
        )
    os.unlink(f.name)

    try:
        report = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        report = {"error": "Bandit failed", "raw": result.stdout}

    return report

@app.post("/api/v1/codeql-scan/python")
async def codeql_scan(body: CodeIn):
    if not body.code:
        raise HTTPException(status_code=400, detail="code is required")

    with tempfile.TemporaryDirectory() as temp_dir:
        code_file_path = os.path.join(temp_dir, "main.py")
        with open(code_file_path, "w") as f:
            f.write(body.code)

        db_path = os.path.join(temp_dir, "codeql-db")

        create_db_command = [
            "codeql", "database", "create", db_path,
            "--language=python",
            f"--source-root={temp_dir}"
        ]
        create_db_result = subprocess.run(create_db_command, capture_output=True, text=True)
        if create_db_result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"CodeQL database creation failed: {create_db_result.stderr}")

        output_sarif_path = os.path.join(temp_dir, "results.sarif")

        codeql_packs_path = os.path.join(os.path.expanduser("~"), ".codeql", "packages")

        analyze_command = [
            "codeql", "database", "analyze", db_path,
            "--format=sarif-latest",
            f"--output={output_sarif_path}",
            f"--search-path={codeql_packs_path}",  # Explicitly provide the search path
            "python-security-and-quality"
        ]

        analyze_result = subprocess.run(analyze_command, capture_output=True, text=True)
        if analyze_result.returncode != 0:
            error_detail = f"CodeQL analysis failed. Return code: {analyze_result.returncode}\n"
            error_detail += f"Stdout: {analyze_result.stdout}\n"
            error_detail += f"Stderr: {analyze_result.stderr}"
            raise HTTPException(status_code=500, detail=error_detail)

        try:
            with open(output_sarif_path, "r") as f:
                report = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            report = {"error": "Failed to read or parse CodeQL report", "details": str(e)}

    return report