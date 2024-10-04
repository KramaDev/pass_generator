import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import hashlib

# Constants for image resizing
TARGET_WIDTH = 128
TARGET_HEIGHT = 128

def generate_hex_password(image_path, max_length=15):
    # Load the image
    img = Image.open(image_path).convert('RGB')
    
    # Resize the image
    img = img.resize((TARGET_WIDTH, TARGET_HEIGHT))
    
    width, height = img.size
    
    # Initialize an empty string to collect pixel values
    pixel_string = ""
    
    # Extract pixel values row by row
    for y in range(height):
        for x in range(width):
            pixel = img.getpixel((x, y))
            # Concatenate RGB values
            pixel_string += f"{pixel[0]:02x}{pixel[1]:02x}{pixel[2]:02x}"

    # Create a SHA-256 hash of the pixel string
    hash_object = hashlib.sha256(pixel_string.encode())
    hex_hash = hash_object.hexdigest()

    # Return the first max_length characters of the hash
    return hex_hash[:max_length]

def upload_image():
    # Open a file dialog to select an image
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png;*.bmp")])
    if file_path:
        password = generate_hex_password(file_path)
        # Store the generated password in a global variable
        global current_password
        current_password = password
        password_label.config(text=f"Last Generated HEX Password: {password}")

def copy_to_clipboard():
    try:
        root.clipboard_clear()  # Clear the clipboard
        root.clipboard_append(current_password)  # Append the current password to the clipboard
        messagebox.showinfo("Copied!", f"HEX Password copied to clipboard: {current_password}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to copy HEX Password: {str(e)}")

# Set up the main application window
root = tk.Tk()
root.title("HEX Password Generator")
root.geometry("400x350")
root.configure(bg="#f0f0f0")

# Title label
title_label = tk.Label(root, text="HEX Password Generator", font=("Helvetica", 16, "bold"), bg="#f0f0f0", fg="#333")
title_label.pack(pady=10)

# Add buttons to upload the image
upload_button = tk.Button(root, text="Upload Image", command=upload_image, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised", padx=10, pady=5)
upload_button.pack(pady=20)

# Label to display the last generated password
password_label = tk.Label(root, text="Last Generated HEX Password will appear here.", font=("Helvetica", 12), bg="#f0f0f0", fg="#333")
password_label.pack(pady=20)

# Button to copy the last generated password
copy_button = tk.Button(root, text="Copy HEX Password", command=copy_to_clipboard, bg="#2196F3", fg="white", font=("Helvetica", 12), relief="raised", padx=10, pady=5)
copy_button.pack(pady=10)

# Footer label
footer_label = tk.Label(root, text="Programmed by KramaDev", font=("Helvetica", 8), bg="#f0f0f0", fg="#666")
footer_label.pack(side=tk.BOTTOM, pady=10)

# Run the application
root.mainloop()
