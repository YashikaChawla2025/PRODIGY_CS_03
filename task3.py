import tkinter as tk
from tkinter import font as tkFont # Import font module for custom fonts
import re

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        # Set a fixed window size for better control over layout
        self.root.geometry("600x650")
        self.root.resizable(False, False) # Prevent resizing
        self.root.config(bg="#1f2128") # Dark background for the main window

        # Define custom fonts for a modern look
        self.title_font = tkFont.Font(family="Segoe UI", size=24, weight="bold")
        self.label_font = tkFont.Font(family="Segoe UI", size=14)
        self.entry_font = tkFont.Font(family="Segoe UI", size=14)
        self.strength_font = tkFont.Font(family="Segoe UI", size=18, weight="bold")
        self.criteria_font = tkFont.Font(family="Segoe UI", size=12)
        self.feedback_font = tkFont.Font(family="Segoe UI", size=12, slant="italic")


        # Title Label
        title = tk.Label(root, text="Password Strength Checker", font=self.title_font, bg="#1f2128", fg="#4caf50")
        title.pack(pady=20)

        # Frame for input and feedback - main content area
        frame = tk.Frame(root, bg="#292c33", padx=25, pady=25, relief="raised", bd=2)
        frame.pack(padx=30, pady=15, fill="both", expand=True)

        # Password Label
        pwd_label = tk.Label(frame, text="Enter Password:", font=self.label_font, bg="#292c33", fg="white")
        pwd_label.pack(anchor="w") # Align to the west (left)

        # Frame to hold password entry and toggle button side-by-side
        entry_toggle_frame = tk.Frame(frame, bg="#292c33")
        entry_toggle_frame.pack(fill="x", pady=(5, 15))

        # Password Entry
        # Changed 'show' attribute from "*" to "." as requested
        self.pwd_entry = tk.Entry(entry_toggle_frame, show=".", font=self.entry_font, bg="#3a3f4b", fg="white", insertbackground="white", relief="flat", bd=0)
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.pwd_entry.bind("<KeyRelease>", self.check_strength) # Bind key release event to strength checker

        # Password Visibility Toggle Button (Eye symbol is already present)
        self.password_visible = False # Initial state: password is hidden
        self.toggle_button = tk.Button(entry_toggle_frame, text="*", font=("Segoe UI", 12), bg="#4a4f5f", fg="white",
                                       command=self.toggle_password_visibility, relief="flat", bd=0, cursor="hand2")
        self.toggle_button.pack(side="right", padx=(5, 0))

        # Strength Label
        self.strength_label = tk.Label(frame, text="No password entered", font=self.strength_font, bg="#292c33", fg="gray")
        self.strength_label.pack(pady=(10, 5)) # Reduced padding to make space for feedback

        # Summary Feedback Label
        self.summary_feedback_label = tk.Label(frame, text="", font=self.feedback_font, bg="#292c33", fg="white", wraplength=400, justify="center")
        self.summary_feedback_label.pack(pady=(0, 15)) # Added a new label for summary feedback

        # Criteria Checklist Frame
        self.criteria_frame = tk.Frame(frame, bg="#292c33")
        self.criteria_frame.pack(pady=(10, 0), anchor="w", fill="x")

        # Dictionary to hold references to criteria labels for easy updating
        self.criteria_labels = {}
        # List of criteria with their display text and corresponding internal key
        self.criteria_list_data = [
            ("At least 8 characters long", 'length'),
            ("An uppercase letter (A-Z)", 'uppercase'),
            ("A lowercase letter (a-z)", 'lowercase'),
            ("A number (0-9)", 'number'),
            # Changed the display text for special characters from '...' to '&'
            ("A special character (!@#$&) ", 'special')
        ]

        # Create labels for each criterion
        for text, key in self.criteria_list_data:
            label = tk.Label(self.criteria_frame, text=f"? {text}", font=self.criteria_font, bg="#292c33", fg="gray")
            label.pack(anchor="w", pady=2)
            self.criteria_labels[key] = label # Store label reference

        # Initial check to set up the UI correctly on start
        self.check_strength()

    def toggle_password_visibility(self):
        """Toggles the visibility of the password in the entry field."""
        if self.password_visible:
            self.pwd_entry.config(show=".") # Hide password with dot symbol
            self.toggle_button.config(text="*") # Change icon to eye
            self.password_visible = False
        else:
            self.pwd_entry.config(show="") # Show password
            self.toggle_button.config(text="**") # Change icon to locked eye
            self.password_visible = True

    def update_criteria_label(self, key, is_met):
        """
        Updates the text and color of a specific criterion label.
        Args:
            key (str): The key of the criterion (e.g., 'length', 'uppercase').
            is_met (bool): True if the criterion is met, False otherwise.
        """
        label = self.criteria_labels[key]
        original_text = next(text for text, k in self.criteria_list_data if k == key) # Get original text
        
        if is_met:
            label.config(text=f"@ {original_text}", fg="#4caf50") # Green for met
        else:
            label.config(text=f"# {original_text}", fg="gray") # Gray for not met

    def check_strength(self, event=None):
        """
        Assesses the password strength and updates the UI accordingly.
        This method is called whenever the user types in the password entry.
        """
        password = self.pwd_entry.get()

        # Booleans to track if each criterion is met
        has_length = len(password) >= 8
        has_uppercase = re.search(r'[A-Z]', password) is not None
        has_lowercase = re.search(r'[a-z]', password) is not None
        has_digit = re.search(r'\d', password) is not None
        # Checks for any character that is NOT a letter, number, or underscore (common special chars)
        has_special_char = re.search(r'[^A-Za-z0-9\s]', password) is not None

        score = 0 # Initialize score for strength calculation
        missing_criteria = [] # List to store missing criteria for feedback

        # Update criteria labels and score
        if has_length: score += 1
        else: missing_criteria.append("at least 8 characters")
        self.update_criteria_label('length', has_length)

        if has_uppercase: score += 1
        else: missing_criteria.append("uppercase letters")
        self.update_criteria_label('uppercase', has_uppercase)

        if has_lowercase: score += 1
        else: missing_criteria.append("lowercase letters")
        self.update_criteria_label('lowercase', has_lowercase)

        if has_digit: score += 1
        else: missing_criteria.append("numbers")
        self.update_criteria_label('number', has_digit)

        if has_special_char: score += 1
        else: missing_criteria.append("special characters")
        self.update_criteria_label('special', has_special_char)

        # Define colors and strength text based on the score
        # The colors correspond to Weak, Very Weak, Moderate, Strong, Very Strong
        colors = {
            0: "#f44336", # Red (Very Weak)
            1: "#f44336", # Red (Very Weak)
            2: "#ff9800", # Orange (Weak)
            3: "#ffeb3b", # Yellow (Moderate)
            4: "#8bc34a", # Light Green (Strong)
            5: "#4caf50"  # Dark Green (Very Strong)
        }
        strengths = {
            0: "Very Weak",
            1: "Very Weak",
            2: "Weak",
            3: "Moderate",
            4: "Strong",
            5: "Very Strong"
        }

        # Update the strength label's text and color
        if not password: # If password is empty
            self.strength_label.config(text="No password entered", fg="gray")
            self.summary_feedback_label.config(text="Start typing to check strength.", fg="gray")
        else:
            self.strength_label.config(text=strengths[score], fg=colors[score])
            # Provide summary feedback
            if score == 5:
                self.summary_feedback_label.config(text="Excellent password! All criteria met....", fg="#4caf50")
            elif missing_criteria:
                feedback_message = "To improve, include: " + ", ".join(missing_criteria) + "."
                self.summary_feedback_label.config(text=feedback_message, fg="white")
            else:
                self.summary_feedback_label.config(text="Good password! Consider making it longer for more strength.", fg="white")


# This block ensures the application runs only when the script is executed directly
if __name__ == "__main__":
    root = tk.Tk() # Create the main Tkinter window
    app = PasswordStrengthChecker(root) # Create an instance of our checker app
    root.mainloop() # Start the Tkinter event loop
