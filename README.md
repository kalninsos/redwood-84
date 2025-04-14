# redwood-84 *IN ACTIVE DEVELOPMENT - UNFINISHED*
Python based desktop app for quantum-proof encryption/decryption of .txt files.
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
