import psutil
import time
from database import init_db, add_event


# Processes that are normally expected on this system
NORMAL_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "explorer.exe",
    "svchost.exe",
    "runtimebroker.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "sihost.exe",
    "conhost.exe",
    "openconsole.exe",
    "powershell.exe",
    "cmd.exe",
    "python.exe",
    "notepad.exe",
    "audiodg.exe",
    "onedrive.exe",
    "onedrivelauncher.exe",
    "officec2rclient.exe",
    "shellhost.exe",
    "taskhostw.exe",
    "sppsvc.exe",
    "hxtsr.exe",
}


def get_running_processes():

    processes = set()

    for process in psutil.process_iter(["pid", "name"]):

        try:
            pid = process.info["pid"]
            name = process.info["name"]

            if name:
                processes.add((pid, name.lower()))

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def start_monitoring():

    init_db()

    print("=" * 55)
    print(" CYBER DECEPTION ACTIVITY COLLECTOR")
    print("=" * 55)
    print("Local activity monitoring: ACTIVE")
    print("Normal processes are filtered.")
    print("Security-relevant activity will be recorded.")
    print("Press CTRL + C to stop.")
    print("=" * 55)

    previous_processes = get_running_processes()

    while True:

        time.sleep(3)

        current_processes = get_running_processes()

        new_processes = current_processes - previous_processes

        for pid, name in new_processes:

            # Ignore normal applications and Windows processes
            if name in NORMAL_PROCESSES:
                continue

            description = (
                f"Unrecognized local process activity detected: "
                f"{name} (PID: {pid})"
            )

            add_event(
                event_type="PROCESS_ACTIVITY",
                source="127.0.0.1",
                description=description,
                severity="MEDIUM"
            )

            print("[SECURITY EVENT]", description)

        previous_processes = current_processes


if __name__ == "__main__":

    try:
        start_monitoring()

    except KeyboardInterrupt:
        print("\nCollector stopped safely.")