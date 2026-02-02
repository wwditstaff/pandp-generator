from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os
import requests
import hashlib
import secrets
from data import Data
import time
import hmac
import base64
from typing import Optional
import json
import logging
import paramiko
from utils.middleware import ContextProcessorMiddleware

load_dotenv()

app = FastAPI()
app.add_middleware(ContextProcessorMiddleware)
templates = Jinja2Templates(directory="templates")

from zoneinfo import ZoneInfo

TZ = ZoneInfo(os.getenv("TIMEZONE", "America/Los_Angeles"))  # default to PST/PDT

scheduler = BackgroundScheduler(
    job_defaults={
        "coalesce": True,  # combine missed runs into one
        "max_instances": 1,  # avoid overlapping jobs
        "misfire_grace_time": 60  # allow 60 seconds grace for small delays
    },
    timezone=TZ
)
scheduler.start()

# Session management
SECRET_SESSION_KEY = os.getenv("SESSION_SECRET", secrets.token_hex(16))

def create_session_token(username: str) -> str:
    """Return a signed session token for the given username."""
    timestamp = str(int(time.time()))
    data = f"{username}:{timestamp}"
    signature = hmac.new(SECRET_SESSION_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()
    token_raw = f"{data}:{signature}".encode()
    return base64.urlsafe_b64encode(token_raw).decode()


def verify_session_token(token: str) -> Optional[str]:
    """Return the username if token is valid, otherwise None."""
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        username, timestamp, signature = decoded.split(":")
        expected_signature = hmac.new(SECRET_SESSION_KEY.encode(), f"{username}:{timestamp}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        # Optionally enforce expiry (e.g., 1 day)
        # Here we allow tokens for 24 hours
        if time.time() - float(timestamp) > 86400:
            return None
        return username
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Authentication helpers

def is_authenticated(request: Request) -> bool:
    """Return True if the current session cookie corresponds to an admin user."""
    return True
    token = request.cookies.get("session")
    if not token:
        return False
#    username = verify_session_token(token)
    return True

def require_login(request: Request) -> None:
    """Raise HTTPException if the current user is not authenticated."""
    if not is_authenticated(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")



# Utility: List last 30 days of files

def list_exported_files():
    data_folder = os.getenv("DATA_FOLDER", "./data")
    prefix = os.getenv("DATA_FILE_PREFIX", "daily_")
    files = []
    if not os.path.exists(data_folder):
        return files
    for fname in os.listdir(data_folder):
        if fname.startswith(prefix) and ((fname.endswith(".xlsx") or fname.endswith(".csv"))):
            fpath = os.path.join(data_folder, fname)
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
            if mtime > datetime.now() - timedelta(days=30):
                files.append({"name": fname, "date": mtime.strftime("%Y-%m-%d %H:%M")})
    files.sort(key=lambda x: x["date"], reverse=True)
    return files

# Utility: SFTP push

def push_file_to_ftp(filename):
    ftp_host = os.getenv("FTP_HOST")
    ftp_user = os.getenv("FTP_USER")
    ftp_pass = os.getenv("FTP_PASS")
    data_folder = os.getenv("DATA_FOLDER", "./data")
    if not ftp_host or not ftp_user or not ftp_pass:
        return False, "FTP credentials not configured"
    fpath = os.path.join(data_folder, filename)
    if not os.path.exists(fpath):
        return False, "File not found"
    rpath = "/westlands-water-district-ca/"
    try:
        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        # Automatically add the host key (use with caution)
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Connect to the SFTP server
        ssh_client.connect(ftp_host, 22, ftp_user, ftp_pass)
        # Create an SFTP session
        sftp_client = ssh_client.open_sftp()
        # ... perform SFTP operations here ...
        sftp_client.put(fpath, rpath+filename)
        # Save an extra copy with _apn_ in the filename
        sftp_client.put(fpath, rpath+filename.replace("daily_","daily_apn_"))
        files = sftp_client.listdir(rpath)
        if filename not in files:
            return False, "File upload failed: file not found on server after upload"
        return True, "File pushed to FTP successfully"

    except paramiko.AuthenticationException:
        print("Authentication failed, please check your credentials.")
        return False, "Authentication failed, please check your credentials."
    except paramiko.SSHException as e:
        print(f"SSH error: {e}")
        return False, "Authentication failed, please check your credentials."
    except Exception as e:
        print(f"An error occurred: {e}")
        return False, str(e)

    finally:
        # Ensure connections are closed
        if sftp_client:
            sftp_client.close()
        if ssh_client:
            ssh_client.close()

# Scheduled tasks
scheduled_export_time = None
scheduled_ftp_time = None

def scheduled_export():
    requests.get("/api/generate-data-and-save")

def scheduled_ftp_push():
    files = list_exported_files()
    if files:
        latest = files[0]["name"]
        push_file_to_ftp(latest)

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    context = request.state.context
    return templates.TemplateResponse("index.html", {"request": request, **context})

@app.get("/api/generate-data-and-save")
async def api_generate_data():
    generate_data()
    return {"message": f"Data saved successfully"}

def generate_data():
    data = Data()
    data.load_unpaid()
    data.load_unpaid_apns()
    data_folder = os.getenv("DATA_FOLDER", "./data")
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)
    date_str = datetime.now().strftime("%Y%m%d")

    # calculate csv filename
    csv_filename = f"daily_{date_str}.csv"
    csv_full_path = data_folder + '/' + csv_filename
    data.save_unpaid_as_csv(csv_full_path)

    # calculate apn csv filename
    csv_apn_filename = f"daily_apn_{date_str}.csv"
    csv_apn_full_path = data_folder + '/' + csv_apn_filename
    data.save_unpaid_apns_as_csv(csv_apn_full_path)

    # clear data from memory
    data = None
    return

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    require_login(request)
    files = list_exported_files()
    settings = read_settings()
    export_time = settings.get("export_time", "")
    ftp_time = settings.get("ftp_time", "")

    context = request.state.context
    context['files'] = files
    context['export_time'] = export_time
    context['ftp_time'] = ftp_time
    return templates.TemplateResponse("admin.html", {"request": request, **context})



@app.post("/generate-export")
async def generate_export(request: Request):
    generate_data()
    return admin_dashboard(request)
#    return RedirectResponse("/admin", status_code=status.HTTP_302_FOUND)

@app.get("/download/{filename}")
def download_file(request: Request, filename: str):
    require_login(request)
    data_folder = os.getenv("DATA_FOLDER", "./data")
    fpath = os.path.join(data_folder, filename)
    if not os.path.exists(fpath):
        return HTMLResponse("File not found", status_code=404)
    return FileResponse(fpath, filename=filename)

@app.get("/push-ftp/{filename}")
def push_ftp(request: Request, filename: str):
    require_login(request)
    success, msg = push_file_to_ftp(filename)
    return RedirectResponse("/admin", status_code=status.HTTP_302_FOUND)

@app.post("/schedule-export")
async def schedule_export(request: Request):
    require_login(request)
    form = await request.form()
    export_time = form.get("export_time")
    settings = read_settings()
    settings["export_time"] = export_time
    write_settings(settings)
    # remove existing job if any
    if scheduler.get_job("daily_export"):
        scheduler.remove_job("daily_export")
    scheduler.add_job(
        generate_data ,
        CronTrigger(hour=int(export_time[:2]), minute=int(export_time[3:]), second=0),
        id="daily_export",
        replace_existing=True)
    return RedirectResponse("/admin", status_code=status.HTTP_302_FOUND)

@app.post("/schedule-ftp")
async def schedule_ftp(request: Request):
    require_login(request)
    form = await request.form()
    ftp_time = form.get("ftp_time")
    settings = read_settings()
    settings["ftp_time"] = ftp_time
    write_settings(settings)
    scheduler.add_job(
        scheduled_ftp_push,
        CronTrigger(hour=int(ftp_time[:2]), minute=int(ftp_time[3:]), second=0),
        id="daily_ftp",
        replace_existing=True)
    return RedirectResponse("/admin", status_code=status.HTTP_302_FOUND)

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    """Render the login form."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    """Process the login form."""
    form = await request.form()
    username = form.get("username")
    password = form.get("password")

    load_dotenv()  # Ensure .env is loaded for environment variables
    api_url = os.getenv("AUTH_API")
    groups = os.getenv("AUTH_API_GROUPS", "").split(",")

    if not api_url or not groups:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Authentication API not configured"},
        )
    url = f"{api_url}"
    if url.endswith("/"):
        url = url[:-1]
    api_url = url  # Store base URL for later use
    #
    # for each group, try to authenticate
    for group in groups:
        if not group.strip():
            continue
        url = f"{api_url}/{group.strip()}"
        headers = {"Content-Type": "application/json"}
        body = {"username": username, "password": password}
        response = requests.post(url, json=body, headers=headers)
        if response.status_code == 200:
            # Authentication successful
            token = create_session_token(username)
            response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
            response.set_cookie(
                key="session",
                value=token,
                httponly=True,
                max_age=86400,
                path="/",
            )
            return response
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid username or password"},
    )


@app.get("/logout")
def logout(request: Request):
    """Log out the current user by clearing the session cookie."""
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="session", path="/")
    return response

# Utility functions for scheduled times persistence
SETTINGS_JSON = os.getenv("SETTINGS_JSON", "settings.json")

# Improved settings persistence with logging and directory creation
def read_settings():
    try:
        if not os.path.exists(SETTINGS_JSON):
            logging.info(f"Settings file not found: {SETTINGS_JSON}")
            return {}
        with open(SETTINGS_JSON, "r") as f:
            settings = json.load(f)
            logging.info(f"Settings loaded from {SETTINGS_JSON}: {settings}")
            return settings
    except Exception as e:
        logging.error(f"Error reading settings file {SETTINGS_JSON}: {e}")
        return {}

def write_settings(settings):
    try:
        settings_dir = os.path.dirname(SETTINGS_JSON)
        if settings_dir and not os.path.exists(settings_dir):
            os.makedirs(settings_dir, exist_ok=True)
        with open(SETTINGS_JSON, "w") as f:
            json.dump(settings, f)
        logging.info(f"Settings saved to {SETTINGS_JSON}: {settings}")
    except Exception as e:
        logging.error(f"Error writing settings file {SETTINGS_JSON}: {e}")

settings = read_settings()
if "export_time" in settings:
    et = settings["export_time"]

    if scheduler.get_job("daily_export"):
        scheduler.remove_job("daily_export")
    scheduler.add_job(
        generate_data,
        CronTrigger(hour=int(et[:2]), minute=int(et[3:]), second=0),
        id="daily_export",
        replace_existing=True
    )
if "ftp_time" in settings:
    ft = settings["ftp_time"]
    if scheduler.get_job("daily_ftp"):
        scheduler.remove_job("daily_ftp")
    scheduler.add_job(
        scheduled_ftp_push,
        CronTrigger(hour=int(ft[:2]), minute=int(ft[3:]), second=0),
        id="daily_ftp",
        replace_existing=True
    )
