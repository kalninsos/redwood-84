import customtkinter
from customtkinter import filedialog
import os
import hashlib #to hash our usernames
from supabase import AuthApiError, create_client, Client
from supabase.client import ClientOptions
from dotenv import load_dotenv
from PIL import Image #for using a picture as a background
import base64

from encryption import AES_Encrypt
from decryption import AES_Decrypt
from lookup_tables import trim_bafo
from parameters import p, g

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

#todo list
#chop padding letters off of final decrypted message
#allow multiple encryptions/decryptions in once instance
#package all of the code into a single executable

username = ""
password = ""
person_to_or_from = ""
data = ""
s_public_key = ""
friend_public_key = ""
can_preform_action = False
has_keys = False

pn = dh.DHParameterNumbers(p, g)
parameters = pn.parameters()

#loading .env file and retrieving supabase url + apikey
load_dotenv()
SUPABASE_URL=os.getenv('SUPABASE_URL')
SUPABASE_KEY=os.getenv('SUPABASE_KEY')

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY, options=ClientOptions(
        postgrest_client_timeout=5,
        storage_client_timeout=5,
        schema="public",
    )
)

class loginFrame(customtkinter.CTkFrame):
    def __init__(self, master, switch_callback):
        super().__init__(master)
        self.switch_callback = switch_callback

        self.incorrect_details = customtkinter.CTkLabel(self, text="Incorrect Username or Password.")

        self.username_textbox = customtkinter.CTkEntry(self, width = 200, height = 25, placeholder_text = 'Username')
        self.username_textbox.grid(row = 1, column = 1, padx = 20, pady = (20,10))

        self.password_textbox = customtkinter.CTkEntry(self, width = 200, height = 25, placeholder_text='Password', show='*')
        self.password_textbox.grid(row = 2, column = 1, padx = 20)

        self.login_button = customtkinter.CTkButton(self, width = 150, height = 20, text="submit login details", command=self.hashAndTestEmail)
        self.login_button.grid(row = 3, column = 1, padx = 20, pady = 20)

    def login(self, email, password):
        try:
            response = supabase.auth.sign_in_with_password(
                {
                "email": email, 
                "password": password,
                }
            )
            if response:
                print("Login Successful!")

                #query the whole row for the logged in user (via email)
                response2 = (supabase.table('keys')
                             .select("email", "public_key")
                             .eq("email",email)
                             .execute()
                )

                if response2:
                    #if public key is default:
                    if response2.data[0]['public_key'] == "1111":
                        print("USER HAS DEFAULT PUBLIC KEY. RUN PUBLIC / PRIVATE KEY GENERATION FUNCTION.")
                        self_private_key = parameters.generate_private_key()

                        #write private key to a .pem file
                        with open("my_dh_private_key.pem", "wb") as f:
                            f.write(self_private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
                            ))

                        self_public_key = self_private_key.public_key()
                        
                        #encoding public key
                        public_der = self_public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )

                        public_b64 = base64.b64encode(public_der).decode("utf-8")
                        #writing public key to database
                        print("attempting to write ", public_b64)
                        response = (
                            supabase.table("keys")
                            .update({"public_key": public_b64})
                            .eq("email", email)
                            .execute()
                            )
                    
                    #public key is not default
                    else:
                        print("User has valid public key.")
                        global s_public_key

                        response = (supabase.table('keys')
                             .select("email", "public_key")
                             .eq("email",email)
                             .execute()
                        )
                        if response:
                            public_b64 = response.data[0]['public_key'] #grab public key for logged in user
                            public_der = base64.b64decode(public_b64)
                            s_public_key = load_der_public_key(public_der)
            
                else:
                    print("Attempting to retrieve keys for check failed.")
                self.switch_callback() #this switches us to the login panel 
                return response
            
        except AuthApiError:
            print("Incorrect Password.")
            self.incorrect_details.grid(row = 0, column = 1, padx = 20, pady = 20)   
 
    def hashAndTestEmail(self):
        global username
        global password
        username = self.username_textbox.get()
        password = self.password_textbox.get()
        email = ""
        hashed_user = hashlib.sha256(username.encode('utf-8')).hexdigest()
        
        #see if the (hashed) username is in our table
        response = (supabase.table('keys')
                         .select("hashed_user", "email")
                         .eq("hashed_user",hashed_user)
                         .execute()
        )

        if not response.data:
            print("Invalid Username.")
            self.incorrect_details.grid(row = 0, column = 1, padx = 20, pady = 20)
        else: #username is valid
            #print(response.data[0]["email"])
            email = response.data[0]["email"]
            self.login(email, password)

class recipientUsernameFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)

        self.warning_text = customtkinter.CTkLabel(self, text="For encryption: specify the RECIPIENT \n For decryption: specify the SENDER")
        self.recipient_username_textbox = customtkinter.CTkEntry(self, width = 200, height = 25, placeholder_text = "Username")
        self.submit_recipient_username = customtkinter.CTkButton(self, width = 150, height = 20, text="submit username", command=self.retrieveRecipientUsername)
        
        self.warning_text.grid(row = 0, columnspan= 2)
        self.recipient_username_textbox.grid(row = 1, column = 0, padx = 20, pady = (10,20))
        self.submit_recipient_username.grid(row = 1, column = 1, padx = 20, pady = (10,20))

    def retrieveRecipientUsername(self):
        recipient = self.recipient_username_textbox.get()
        print(f"Recipient is: {recipient}")
        hashed_recipient = hashlib.sha256(recipient.encode('utf-8')).hexdigest()

        response = (supabase.table('keys')
                         .select("hashed_user")
                         .eq("hashed_user",hashed_recipient)
                         .execute()
        )

        if response:
            global person_to_or_from, can_preform_action, has_keys
            if not response.data: #if hashed recipient doesn't exist
                can_preform_action = False
                print("Invalid recipient. Please check the spelling of your recipient.")
                self.warning_text.configure(text="Invalid recipient. Please check the spelling of your recipient.")

            else: #if hashed recipient DOES exist
                #query the keys of the person we want to encrypt for/decrypt from
                response2 = (supabase.table('keys')
                             .select("hashed_user", "public_key")
                             .eq("hashed_user", hashed_recipient)
                             .execute()
                )

                if response2:
                    #if public key is default:
                    if response2.data[0]['public_key'] == "1111":
                        has_keys = False
                        print("User has not logged in before. Please ask them to login, then retry.")
                        self.warning_text.configure(text="User has not logged in before. Please ask them to login, then retry.")
                    
                    #if public key is already established, retrieve public key for that user (friend we are decrypting to/from)
                    else:
                        global friend_public_key
                        public_b64 = response2.data[0]['public_key']
                        public_der = base64.b64decode(public_b64)
                        friend_public_key = load_der_public_key(public_der)
                        print("User is verified. Proceed with e/d")
                        self.warning_text.configure(text="User is verified. Proceed with encryption or decryption.")
                        person_to_or_from = recipient
                        can_preform_action = True
                else:
                    print("Attempting to retrieve keys for check failed.")

class mainProgramFrame(customtkinter.CTkFrame):
    def __init__(self, master, switch_callback):
        super().__init__(master)

        self.switch_callback = switch_callback

        self.welcome_label = customtkinter.CTkLabel(self, text=f"Welcome, {username}. Please load a text file to begin.")
        self.welcome_label.grid(row = 0, column = 1)

        self.loadfile_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Load Text File", command=self.loadFile)
        self.loadfile_button.grid(row = 1, column = 0, padx = 20, pady = 20)

        self.encrypt_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Encrypt a File", command=self.encrypt) 
        self.encrypt_button.grid(row = 1, column = 1, padx = 20, pady = 20)

        self.decrypt_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Decrypt a File", command=self.decrypt)
        self.decrypt_button.grid(row = 1, column = 2, padx = 20, pady = 20)

        self.alert = customtkinter.CTkLabel(self, text=f"Placeholder text for Encryption/Decryption Success or failure")

    def loadFile(self):
        global data
        print('User is loading file...')
        userfile = filedialog.askopenfilename() #userfile is the path to the file we want to encrypt
        print('User selected file: ', userfile)

        with open(userfile, "r") as file:
            data = file.read().replace('\n', ' ')

        self.switch_callback() #reveal "enter recipient username" frame
    
    def derive_key(self):
        #retrieve private key from .pem file
        with open("my_dh_private_key.pem", "rb") as f:
            private_key = load_pem_private_key(f.read(), password=password.encode())
        
        #derive shared key
        self_shared_key = private_key.exchange(friend_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self_shared_key)
        derived_key = derived_key.hex()[0:32] #only need 16 bytes for AES128, so take the first 16

        return derived_key
        
    def encrypt(self):
        global data

        if can_preform_action == True:
            print('User chose to encrypt!')
            #retrieve shared key from Supabase and then derive the actual key we can use
            d_key = self.derive_key()
            print("Our derived key is: ", d_key)

            encrypted_data = AES_Encrypt(data, d_key)
            print(f"encrypted data: {encrypted_data}")
            with open("encrypted.txt", "w") as file:
                file.write(encrypted_data)
            
            self.action_result("encrypted.txt", "encrypt")

        if can_preform_action == False:
            print('CPF is False, likely an invalid friend user')

    def decrypt(self):
        global data

        if can_preform_action == True:
            print('User chose to decrypt!')
            #retrieve shared key from Supabase and then derive the actual key we can use
            d_key = self.derive_key()
            print("Our derived key is: ", d_key)

            chop_char = data[-1] #character representing the amount to chop
            decrypted_data = AES_Decrypt(data[:-1], d_key) #pass through the whole string (except the last char, that corresponds to amt to chop)
            decrypted_data = self.chop_padding(decrypted_data, chop_char)

            with open("decrypted.txt", "w") as file:
                file.write(decrypted_data)
            
            self.action_result("decrypted.txt", "decrypt")

        if can_preform_action == False:
            print("Cannot encrypt, user to encrypt to/from is invalid.")
    
    def action_result(self, filename, operation):
        try:
            with open(filename, "r") as file:
                self.alert.configure(text=f"{operation}ion succeded, file: {filename}")
                self.alert.grid(row = 2, column = 1)
        except:
            FileNotFoundError
            self.alert.configure(text=f"{operation}ion failed.")
            self.alert.grid(row = 2, column = 1)
    
    def chop_padding(self, text, amount_to_chop):
        if amount_to_chop == 'a': #no chopping required
            return text
        else:
            chop_amount = trim_bafo.index(amount_to_chop) #use lookup table to find amt to chop (amt is the index)
            text = text[:-chop_amount]
            return text
            
class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title('redwood84')
        self.geometry('800x640')
        self.grid_columnconfigure(0, weight=1)

        self.login_frame = loginFrame(self, self.show_main_frame)
        self.login_frame.grid(row=0, column=0, padx=20, pady=(200,0))

        #uncomment if we delete the welcome message in mainProgramFrame
        # self.mainprogram_frame = mainProgramFrame(self, self.show_recipient_frame)
        # self.mainprogram_frame.grid(row = 0, column = 0, padx=20, pady=(200,0))
        # self.mainprogram_frame.grid_forget()

        self.recipient_user_frame = recipientUsernameFrame(self)
        self.recipient_user_frame.grid(row = 0, column = 0, padx=20, pady=(200,0))
        self.recipient_user_frame.grid_forget()

    #mainProgramFrame is defined here so it is created after username variable is saved + used for welcome message in MPF
    def show_main_frame(self):
        self.login_frame.grid_forget() #hide login panel
        self.mainprogram_frame = mainProgramFrame(self, self.show_recipient_frame)
        self.mainprogram_frame.grid(row = 0, column = 0, padx=20, pady=(200,0)) #show main program frame
    
    def show_recipient_frame(self):
        self.recipient_user_frame.grid(row = 1, column = 0, padx=20, pady=(10,0)) #show recipient frame
        
app = App()
app.mainloop()
