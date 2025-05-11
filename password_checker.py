import tkinter as tk
from tkinter import ttk
import re
import random
import string
from tkinter import messagebox
try:
    import pyperclip
except ImportError:
    # Create a fallback if pyperclip isn't installed
    class PyperclipFallback:
        def copy(self, text):
            pass
    pyperclip = PyperclipFallback()

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f5f5")
        
        # Set application icon
        try:
            self.root.iconbitmap("lock_icon.ico")
        except:
            pass
            
        # Styling
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f5f5f5')
        self.style.configure('TLabel', background='#f5f5f5', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10, 'bold'))
        self.style.configure('Header.TLabel', font=('Arial', 18, 'bold'))
        
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        ttk.Label(self.main_frame, text="Password Strength Checker", 
                 style='Header.TLabel').pack(pady=(0, 20))
        
        # Author label
        ttk.Label(self.main_frame, 
                 text="Developed by Yash (Popeye)", 
                 font=('Arial', 8, 'italic')).pack(pady=(0, 20))
        
        # Password entry frame
        password_frame = ttk.Frame(self.main_frame)
        password_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(password_frame, text="Enter Password: ").pack(side=tk.LEFT)
        
        self.password_var = tk.StringVar()
        self.password_var.trace("w", self.check_password)
        
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, 
                                      show="•", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        self.show_password = tk.BooleanVar()
        self.show_password.set(False)
        
        show_check = ttk.Checkbutton(password_frame, text="Show", 
                                    variable=self.show_password, 
                                    command=self.toggle_password_visibility)
        show_check.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        ttk.Label(self.main_frame, text="Strength:").pack(anchor=tk.W)
        
        self.progress_frame = ttk.Frame(self.main_frame)
        self.progress_frame.pack(fill=tk.X, pady=(5, 15))
        
        self.progress = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, 
                                      length=400, mode='determinate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.strength_label = ttk.Label(self.progress_frame, text="", width=10)
        self.strength_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Criteria frame
        criteria_frame = ttk.LabelFrame(self.main_frame, text="Password Criteria", padding=10)
        criteria_frame.pack(fill=tk.X)
        
        # Criteria labels
        self.length_var = tk.StringVar(value="❌ Length (8+ chars)")
        self.uppercase_var = tk.StringVar(value="❌ Uppercase letter")
        self.lowercase_var = tk.StringVar(value="❌ Lowercase letter")
        self.number_var = tk.StringVar(value="❌ Number")
        self.special_var = tk.StringVar(value="❌ Special character")
        
        ttk.Label(criteria_frame, textvariable=self.length_var).pack(anchor=tk.W, pady=2)
        ttk.Label(criteria_frame, textvariable=self.uppercase_var).pack(anchor=tk.W, pady=2)
        ttk.Label(criteria_frame, textvariable=self.lowercase_var).pack(anchor=tk.W, pady=2)
        ttk.Label(criteria_frame, textvariable=self.number_var).pack(anchor=tk.W, pady=2)
        ttk.Label(criteria_frame, textvariable=self.special_var).pack(anchor=tk.W, pady=2)
        

        
        # Bottom buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        # Reset button
        reset_button = ttk.Button(button_frame, text="Reset", command=self.reset)
        reset_button.pack(side=tk.LEFT)
        
        # Password Generator popup button
        generate_button = ttk.Button(button_frame, text="Password Generator", 
                                   command=self.open_password_generator)
        generate_button.pack(side=tk.RIGHT)
        
        # Set focus to password entry
        self.password_entry.focus()
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def check_password(self, *args):
        """Check password strength and update UI"""
        password = self.password_var.get()
        
        # Initialize criteria checks
        has_length = len(password) >= 8
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_number = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        
        # Update criteria labels
        self.length_var.set(f"{'✅' if has_length else '❌'} Length (8+ chars)")
        self.uppercase_var.set(f"{'✅' if has_uppercase else '❌'} Uppercase letter")
        self.lowercase_var.set(f"{'✅' if has_lowercase else '❌'} Lowercase letter")
        self.number_var.set(f"{'✅' if has_number else '❌'} Number")
        self.special_var.set(f"{'✅' if has_special else '❌'} Special character")
        
        # Calculate strength (0-100)
        criteria_count = sum([has_length, has_uppercase, has_lowercase, has_number, has_special])
        
        # Additional length bonus
        length_bonus = min(20, max(0, len(password) - 8) * 2) if len(password) >= 8 else 0
        
        # Calculate strength percentage
        strength = min(100, (criteria_count * 15) + length_bonus)
        
        # If password is empty, reset
        if not password:
            strength = 0
        
        # Update progress bar
        self.progress['value'] = strength
        
        # Set progress bar color and strength label
        if strength < 40:
            self.progress['style'] = 'red.Horizontal.TProgressbar'
            self.strength_label.config(text="Weak", foreground="red")
        elif strength < 70:
            self.progress['style'] = 'yellow.Horizontal.TProgressbar'
            self.strength_label.config(text="Moderate", foreground="orange")
        else:
            self.progress['style'] = 'green.Horizontal.TProgressbar'
            self.strength_label.config(text="Strong", foreground="green")
            
        # Configure progress bar styles
        self.style.configure('red.Horizontal.TProgressbar', 
                           background='red')
        self.style.configure('yellow.Horizontal.TProgressbar', 
                           background='orange')
        self.style.configure('green.Horizontal.TProgressbar', 
                           background='green')
    
    def reset(self):
        """Reset the form"""
        self.password_var.set("")
        self.password_entry.focus()
    
    def open_password_generator(self):
        """Open the password generator window"""
        generator_window = tk.Toplevel(self.root)
        generator_window.title("Password Generator")
        generator_window.geometry("400x300")
        generator_window.resizable(False, False)
        generator_window.transient(self.root)  # Make it appear on top of the main window
        generator_window.grab_set()  # Make it modal
        
        # Configure style for the new window
        style = ttk.Style(generator_window)
        style.theme_use('clam')
        
        # Main frame
        main_frame = ttk.Frame(generator_window, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Generate Strong Password", 
                font=('Arial', 14, 'bold')).pack(pady=(0, 15))
        
        # Length settings
        length_frame = ttk.Frame(main_frame)
        length_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT)
        
        length_var = tk.IntVar(value=12)
        length_display = ttk.Label(length_frame, text="12", width=3)
        length_display.pack(side=tk.RIGHT)
        
        length_scale = ttk.Scale(length_frame, from_=8, to=30, 
                               orient=tk.HORIZONTAL, 
                               variable=length_var,
                               command=lambda v: length_display.config(text=str(int(float(v)))))
        length_scale.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Character types
        char_frame = ttk.LabelFrame(main_frame, text="Include Character Types", padding=10)
        char_frame.pack(fill=tk.X, pady=10)
        
        # Character type variables
        uppercase_var = tk.BooleanVar(value=True)
        lowercase_var = tk.BooleanVar(value=True)
        numbers_var = tk.BooleanVar(value=True)
        special_var = tk.BooleanVar(value=True)
        
        # Character type checkboxes
        ttk.Checkbutton(char_frame, text="Uppercase (A-Z)", 
                      variable=uppercase_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(char_frame, text="Lowercase (a-z)", 
                      variable=lowercase_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(char_frame, text="Numbers (0-9)", 
                      variable=numbers_var).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(char_frame, text="Special (!@#$%^&*)", 
                      variable=special_var).grid(row=1, column=1, sticky=tk.W)
        
        # Generated password display
        ttk.Label(main_frame, text="Generated Password:").pack(anchor=tk.W, pady=(10, 5))
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=password_var, width=40)
        password_entry.pack(fill=tk.X)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        # Function to generate password
        def generate():
            # Check that at least one character type is selected
            if not any([uppercase_var.get(), lowercase_var.get(), 
                       numbers_var.get(), special_var.get()]):
                messagebox.showerror("Error", "Select at least one character type", 
                                   parent=generator_window)
                return
            
            # Initialize character pools
            chars = ""
            required_chars = []
            
            # Add selected character types to pool
            if uppercase_var.get():
                chars += string.ascii_uppercase
                required_chars.append(random.choice(string.ascii_uppercase))
                
            if lowercase_var.get():
                chars += string.ascii_lowercase
                required_chars.append(random.choice(string.ascii_lowercase))
                
            if numbers_var.get():
                chars += string.digits
                required_chars.append(random.choice(string.digits))
                
            if special_var.get():
                special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
                chars += special_chars
                required_chars.append(random.choice(special_chars))
            
            # Ensure length is at least enough for required characters
            length = length_var.get()
            if length < len(required_chars):
                length = len(required_chars)
                length_var.set(length)
                length_display.config(text=str(length))
            
            # Start with required characters
            password = ''.join(required_chars)
            
            # Fill rest with random characters
            password += ''.join(random.choice(chars) for _ in range(length - len(required_chars)))
            
            # Shuffle the password
            pwd_list = list(password)
            random.shuffle(pwd_list)
            password = ''.join(pwd_list)
            
            # Set the password
            password_var.set(password)
            
            # Select the text for easy copying
            password_entry.select_range(0, tk.END)
            password_entry.focus()
        
        # Function to use generated password
        def use_password():
            password = password_var.get()
            if not password:
                messagebox.showwarning("No Password", "Generate a password first", 
                                     parent=generator_window)
                return
                
            self.password_var.set(password)
            generator_window.destroy()
        
        # Function to copy to clipboard
        def copy_to_clipboard():
            password = password_var.get()
            if not password:
                messagebox.showwarning("No Password", "Generate a password first", 
                                     parent=generator_window)
                return
                
            try:
                pyperclip.copy(password)
                messagebox.showinfo("Copied", "Password copied to clipboard", 
                                  parent=generator_window)
            except Exception as e:
                messagebox.showerror("Error", f"Could not copy to clipboard: {str(e)}", 
                                   parent=generator_window)
        
        # Add buttons
        ttk.Button(button_frame, text="Generate", 
                 command=generate).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Copy to Clipboard", 
                 command=copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Use Password", 
                 command=use_password).pack(side=tk.RIGHT)
        
        # Generate initial password
        generate()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    
    # Configure progress bar styles
    style = ttk.Style()
    style.configure('red.Horizontal.TProgressbar', background='red')
    style.configure('yellow.Horizontal.TProgressbar', background='orange')
    style.configure('green.Horizontal.TProgressbar', background='green')
    
    root.mainloop()
