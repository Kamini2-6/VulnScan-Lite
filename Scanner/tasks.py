from celery import Celery
from Scanner.scan_site import scan_site


celery_app = Celery(
    "vulnscan",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)


@celery_app.task(
    name="Scanner.tasks.scan_task"
)
def scan_task(url):
    print(f"[*] Celery received URL: {url}")

    result = scan_site(url)

    print("[+] Scan completed")

    return result