import customtkinter
from customtkinter import filedialog
import os
import hashlib #to hash our usernames
from supabase import AuthApiError, create_client, Client
from supabase.client import ClientOptions
from dotenv import load_dotenv
from PIL import Image #for using a picture as a background

from encryption import AES_Encrypt
from decryption import AES_Decrypt

username = ""
person_to_or_from = ""
can_preform_action = False
data = ""
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

                response2 = (supabase.table('keys')
                             .select("email", "public_key")
                             .eq("email",email)
                             .execute()
                )

                if response2:
                    #if public key is default:
                    if response2.data[0]['public_key'] == 1111:
                        print("USER HAS DEFAULT PUBLIC KEY. RUN PUBLIC / PRIVATE KEY GENERATION FUNCTION.")
                    else:
                        print("User has valid public key.")
                else:
                    print("Attempting to retrieve keys for check failed.")
                self.switch_callback() #this switches us to the login panel 
                return response
            
        except AuthApiError:
            print("Incorrect Password.")
            self.incorrect_details.grid(row = 0, column = 1, padx = 20, pady = 20)   
 
    def hashAndTestEmail(self):
        global username
        username = self.username_textbox.get()
        password = self.password_textbox.get()
        email = ""
        hashed_user = hashlib.sha256(username.encode('utf-8')).hexdigest()
        
        response = (supabase.table('keys')
                         .select("hashed_user", "email")
                         .eq("hashed_user",hashed_user)
                         .execute()
        )

        if not response.data:
            print("Invalid Username.")
            self.incorrect_details.grid(row = 0, column = 1, padx = 20, pady = 20)
        else:
            print(response.data[0]["email"])
            email = response.data[0]["email"]
            self.login(email, password)
        
        #below is deprecated
        # login_details=os.getenv('DETAILS')
        # key_value_pairs = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', login_details)

        # for key_value_pair in key_value_pairs:
        #     key, value = key_value_pair.split("=")
        #     if hashed_user == key:
        #         email = value
        #         login_successful = True
        #         self.login(email, password)
        #         break
        #     elif hashed_user != key:
        #         login_successful == False
        # if login_successful == False:
        #     print('no matches found, login unsuccessful.')
        # print(f'our email is: {email} our username is: {username} and our password is: {password}')

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
            global person_to_or_from, can_preform_action
            if not response.data: #if hashed recipient doesn't exist
                can_preform_action = False
                print("Invalid recipient. Please check the spelling of your recipient.")
                self.warning_text.configure(text="Invalid recipient. Please check the spelling of your recipient.")
            else:
                person_to_or_from = recipient
                can_preform_action = True
                print("Recipient is verified. Proceed with Encryption.")
                self.warning_text.configure(text="Recipient is verified. Proceed with encryption.")

class mainProgramFrame(customtkinter.CTkFrame):
    def __init__(self, master, switch_callback):
        super().__init__(master)

        self.switch_callback = switch_callback

        self.welcome_label = customtkinter.CTkLabel(self, text=f"Welcome, {username}. Please load a text file to begin.")
        self.welcome_label.grid(row = 0, column = 1)

        self.loadfile_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Load Text File", command=self.loadFile) #currently no command
        self.loadfile_button.grid(row = 1, column = 0, padx = 20, pady = 20)

        self.encrypt_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Encrypt a File", command=self.encrypt) #currently no command
        self.encrypt_button.grid(row = 1, column = 1, padx = 20, pady = 20)

        self.decrypt_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Decrypt a File", command=self.decrypt) #currently no command
        self.decrypt_button.grid(row = 1, column = 2, padx = 20, pady = 20)
    
    def loadFile(self):
        global data
        print('User is loading file...')
        userfile = filedialog.askopenfilename() #userfile is the path to the file we want to encrypt
        print('User selected file: ', userfile)

        with open(userfile, "r") as file:
            data = file.read().replace('\n', ' ')

        self.switch_callback() #reveal "enter recipient username" frame
        
    def encrypt(self):
        global data

        if can_preform_action == True:
            print('User chose to encrypt!')
            #retrieve shared key from Supabase and then derive the actual key we can use
            key = '2b7e151628aed2a6abf7158809cf4f3c'
            encrypted_data = AES_Encrypt(data, key)
            print(f"encrypted data: {encrypted_data}")

        if can_preform_action == False:
            print('CPF is False for some reason')

    def decrypt(self):
        global data

        if can_preform_action == True:
            print('User chose to decrypt!')
            #retrieve shared key from Supabase and then derive the actual key we can use
            key = '2b7e151628aed2a6abf7158809cf4f3c'
            decrypted_data = AES_Decrypt(data, key)
            print(f"Our decrypted data is: {decrypted_data}")

        if can_preform_action == False:
            print("Cannot encrypt, user to encrypt to/from is invalid.")


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
