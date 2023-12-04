import win32evtlog
import datetime, time
import os
import psutil

# Název souboru pro uložení logů
filename = "system_logs.txt"

# Získání aktuálního času
now = datetime.datetime.now()

# Výpočet času před 10 vteřinami
ten_seconds_ago = now - datetime.timedelta(seconds=100000)

# Otevření systémových logů
log_handle = win32evtlog.OpenEventLog(None, "System")

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ



    


with open(filename, "a") as file:
    while True:
        # Získání informací o všech aktuálně spuštěných procesech
        process_info = [str(proc.info) for proc in psutil.process_iter(['pid', 'name'])]

        # Zápis všech informací o procesech do souboru najednou
        file.write("\n".join(process_info))

        events = win32evtlog.ReadEventLog(log_handle, flags, 0)
        if events:
            for event in events:
                # Převod času události na formát datetime
                event_time = event.TimeGenerated
            
                # Kontrola, zda se událost stala v posledních 10 vteřinách
                if event_time > ten_seconds_ago:
                    # Zápis události do souboru
                    file.write(f"Source Name: {event.SourceName}\n")
                    file.write(f"Time Generated: {event.TimeGenerated}\n")
                    file.write(f"Event ID: {event.EventID}\n")
                    file.write(f"Event Type: {event.EventType}\n")
                    file.write("\n")
        else:
            break
        time.sleep(5)
