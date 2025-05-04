# redwood-84
Python based desktop app for quantum-resistant encryption/decryption of .txt files.
Encryption is 128bit AES.
Login verification and retrieving keys is done via Supabase.
Application is written using Customtkinter.

Explanations (for personal use):
Supabase does not support login with username and password. This program is built for utmost  
security and anonymity. As a result, username and password login is needed.  

The most anonymous login we can use is an email/password combination with spoofed emails.
In the Supabase database we store hashed usernames alongside emails. When a user tries to  
login, we hash their username and search the database for it. If it is a valid username,  
we will retrieve the spoofed email associated with the account and send a login request  
with the email and password.

<img width="799" alt="rw84 Main Page" src="https://github.com/user-attachments/assets/c5c8dac6-c59e-4f43-8a83-3b36ccfc6c65" />
