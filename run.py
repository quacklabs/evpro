import os
import sys
import pyfiglet
from checker import start_checker
from EEPro import Engine


def clear_console():
    """Clear the console based on the operating system."""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_intro():    
    # Print ASCII title with pyfiglet
	title = pyfiglet.figlet_format("Email Toolkit")
	print(title)
	print("Email Toolkit v1.0 - Author: Trakand R&D")

def main_menu():
	clear_console()
	show_intro()
	print(f"Select an option:")
	print(f"1. Email Sender")
	print(f"2. SMTP Checker")
	print(f"3. Email Validator")
	print(f"4. Exit")
	choice = input(f"Enter your choice:")

	if choice == "1":
		print("Coming Soon")
		sys.exit()
	elif choice == "2":
		engine = Engine()
		print(f"Select your smtp file:")
		file_path = engine.select_file([("Text Files", "*.txt")])
		results = start_checker(file_path)
		for result in results:
			print(result)

	elif choice == "3":
		print("Coming Soon...")
		sys.exit()
	elif choice == "4":
		sys.exit()
	else:
		print(f"Invalid choice. Please try again.")
		main_menu()

if __name__ == "__main__":
	main_menu()
