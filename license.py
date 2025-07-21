from datetime import datetime
import pytz
import tzlocal as tzl;
import requests
from tkinter import Tk, messagebox


class License:

	def __init__(self):
		return

	def check_license(self):
		return "OK"
	    # try:
	    #     # Get the system timezone
	    #     local_tz = str(tzl.get_localzone()).replace(" ", "_")
	    #     time_server_url = f"https://worldtimeapi.org/api/timezone/{local_tz}"

	    #     response = requests.get(time_server_url)
	    #     response.raise_for_status()
	    #     server_time = datetime.fromisoformat(response.json()['utc_datetime'].replace("Z", "+00:00"))
	    #     system_time = datetime.now(pytz.utc)

	    #     time_difference = abs((server_time - system_time).total_seconds())
	    #     if time_difference > 60 or time_difference < -60:
	    #         return "Your system time is not in sync. Please update your date and time settings."
	    #         # return False

	    #     # Replace '2024-10-08' with your desired cutoff date
	    #     # 
	    #     cutoff_date = datetime.fromisoformat("2024-10-13T10:42:52.168310+00:00")
	    #     if system_time > cutoff_date:
	    #         return "This product is expired, please purchase a live copy"
	    #         # return False

	    #     return "OK"

	    # except requests.exceptions.RequestException as e:
	    #     # return False
	    #     return "Please check your internet connection or firewall."


