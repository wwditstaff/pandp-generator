import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
# from auth import Auth
import os
import json
from dotenv import load_dotenv
from starlette.responses import Response

load_dotenv()  # Load environment variables from .env file

class ContextProcessorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Prepare base context for this request
        request.state.context = {
            "appname": os.environ.get("APPNAME", "App Name"),
        }
        response: Response = await call_next(request)
        # If this is a TemplateResponse (FastAPI/Starlette adds 'context') ensure appname exists
        if hasattr(response, "context") and isinstance(getattr(response, "context", None), dict):
            response.context.setdefault("appname", request.state.context["appname"])
        return response

class ClientIPLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host  # Extract client IP address
        logging.info(f"Client IP: {client_ip} - {request.method} {request.url}")
        response = await call_next(request)
        return response

# Existing settings loader retained (unused now for appname) but left for future extension

def settings_loader():
    pass
    # app_data_folder = os.getenv("APP_DATA", "~/")
    # settings_file = os.path.join(app_data_folder, "settings.json")
    # if os.path.exists(settings_file):
    #     with open(settings_file, "r") as f:
    #         settings = json.load(f)
    #         os.environ["base_folder"] = settings.get("base_folder", "./")
    #         os.environ["company"] = settings.get("company", "Default Company")
    #         os.environ["upload_folder"] = settings.get("upload_folder", "./")
    #         os.environ["search_pattern"] = settings.get("search_pattern", "Account Number\\n(\\d+)\\b")
    #         os.environ["test_flag"] = settings.get("test_flag", "off")
    #         os.environ["test_email"] = settings.get("test_email", "")
    # else:
    #     os.environ["BASE_FOLDER"] = "./"
    #     os.environ["company"] = "Default Company"
    #     os.environ["upload_folder"] = "./"
    #     os.environ["search_pattern"] = "Account Number\\n(\\d+)\\b"
    #     os.environ["test_flag"] = "off"
    #     os.environ["test_email"] = ""
