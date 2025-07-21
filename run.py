import os
import sys
import pyfiglet
from checker import start_checker
from sender import detonate, show_intro as sender_intro  # Import detonate from sender script
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
    print("Select an option:")
    print("1. Email Sender")
    print("2. SMTP Checker")
    print("3. Email Validator")
    print("4. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        engine = Engine()
        sender_intro()
        print("Please upload your recipient email list")
        email_file_path = engine.select_file([("Text Files", "*.txt")])
        print("Please upload your SMTP credentials file (format: host|port|username|password)")
        smtp_file_path = engine.select_file([("Text Files", "*.txt")])
        print("Please upload message file")
        message_file_path = engine.select_file([("Text Files", "*.txt"), ("HTML Files", "*.html")])
        
        if email_file_path and smtp_file_path and message_file_path:
            print("Enter email subject: ")
            email_subject = input()
            if email_subject:
                try:
                    total_sent, total_failed = detonate(email_file_path, smtp_file_path, message_file_path, email_subject)
                    print(f"Email processed successfully. Sent: {total_sent}, Failed: {total_failed}")
                except Exception as e:
                    print(f"Error during email sending: {str(e)}")
            else:
                print("Subject cannot be empty.")
            input("Press Enter to return to menu...")
        else:
            print("No files selected.")
            print("You must select all required files to proceed.")
            input("Press Enter to return to menu...")
        main_menu()
    elif choice == "2":
        engine = Engine()
        print("Select your SMTP file:")
        file_path = engine.select_file([("Text Files", "*.txt")])
        results = start_checker(file_path)
        for result in results:
            print(result)
        input("Press Enter to return to menu...")
        main_menu()
    elif choice == "3":
        print("Coming Soon...")
        input("Press Enter to return to menu...")
        main_menu()
    elif choice == "4":
        sys.exit()
    else:
        print("Invalid choice. Please try again.")
        input("Press Enter to try again...")
        main_menu()

if __name__ == "__main__":
    main_menu()