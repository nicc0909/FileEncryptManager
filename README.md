# File Encryption Manager
![image](https://github.com/nicc0909/FileEncryptManager/assets/82878594/c5a94389-2919-4c5e-93d5-66bb0ae86e4d)

This project features a file management system with enhanced encryption capabilities. Built using Python, it incorporates libraries such as Tkinter and Cryptography to offer a graphical user interface and secure file handling.

## Key Features:

- **Graphical User Interface**: Crafted with Tkinter and ttkbootstrap, it offers intuitive navigation and a user-friendly experience.
- **File Encryption and Decryption**: Utilizes the Cryptography library for securely encrypting and decrypting files. Supports generating custom encryption keys based on passwords.
- **Efficient File Management**: Enables users to upload, download, view, delete, and rename files within a secure environment. Files are encrypted on upload and decrypted during download.
- **Secure Password Handling**: Implements bcrypt for robust password hashing and verification. Includes functionality to set and reset passwords securely.
- **Automatic File Cleanup**: Employs threading and atexit for managing temporary files, ensuring that decrypted files are securely deleted after use.
- **Comprehensive File Information**: Displays detailed file information including size, type, and last modified timestamps.
- **User Authentication**: Features a password-based access system to the file manager, enhancing security.
- **Customizable Settings and Paths**: Allows setting default paths and adjusting settings for user-specific requirements.

## Dependencies:

- Tkinter
- ttkbootstrap
- Pillow
- Cryptography
- Bcrypt
- Json

The following commands must be executed to install the dipedences.

    > pip install ttkbootstrap 
    > pip install Pillow 
    > pip install cryptography
    > pip install bcrypt

This file manager stands out for its focus on security and user-friendly interface, making it suitable for managing sensitive files with ease and confidence.

initial password : 1234

    



