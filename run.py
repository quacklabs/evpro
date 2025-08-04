import os
import sys
import pyfiglet
from checker import start_checker
from sender import main as sender_main  # Import detonate from sender script
from EEPro import Engine
from validator import main as validator_main
from sender_pro import main as sender_main
from validate import main as validate_main

def clear_console():
    """Clear the console based on the operating system."""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_intro():    
    # Print ASCII title with pyfiglet
    title = pyfiglet.figlet_format("Email Toolkit")
    print(title)
    print("Email Toolkit v1.0 - Author: Trakand R&D")

def main_menu():
    engine = Engine()
    clear_console()
    show_intro()
    print("Select an option:")
    print("1. Email Sender")
    print("2. SMTP Checker")
    print("3. Email Validator")
    print("4. Email Sender (Zero SMTP config)")
    print("5. Outlook/Office365 Validator")
    print("6. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        sender_main()
        main_menu()
    elif choice == "2":
        
        print("Select your SMTP file:")
        file_path = engine.select_file([("Text Files", "*.txt")])
        results = start_checker(file_path)
        for result in results:
            print(result)
        input("Press Enter to return to menu...")
        main_menu()
    elif choice == "3":
        validator_main()
        # print("Select your email list file:")
        # file_path = engine.select_file([("Text Files", "*.txt")])
        # results = start_checker(file_path)
        # for result in results:
        #     print(result)
        # input("Press Enter to return to menu...")

        main_menu()
    elif choice == "4":
        sender_main()
        main_menu()
    elif choice == "5":
        validate_main()
        main_menu()
    elif choice == "6":

        sys.exit()
    else:
        print("Invalid choice. Please try again.")
        input("Press Enter to try again...")
        main_menu()

if __name__ == "__main__":
    main_menu()