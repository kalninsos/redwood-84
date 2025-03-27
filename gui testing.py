import customtkinter
from customtkinter import filedialog
import os
import hashlib #to hash our usernames
from supabase import AuthApiError, create_client, Client
from supabase.client import ClientOptions
from dotenv import load_dotenv

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

#inserting values into our table
#supabase.table("login_details").insert({"email": "avalidemail@email.com", "public_key" : "38902183920183921"}).execute()

#for signing up new users MAKE SURE TO CHANGE EMAIL AAAAANDDDD PASSWORD THANK YOU!!!
# response = supabase.auth.sign_up(
#     {
#         "email": "avalidemail@email.com",
#         "password": "goodpassword",
#     }
# )

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

        self.warning_text = customtkinter.CTkLabel(self, text="For encrypting a message, you MUST specify the recipient.")
        self.recipient_username_textbox = customtkinter.CTkEntry(self, width = 200, height = 25, placeholder_text = "Recipient's Username")
        self.submit_recipient_username = customtkinter.CTkButton(self, width = 150, height = 20, text="submit username", command=self.retrieveRecipientUsername)
        
        self.warning_text.grid(row = 0, columnspan= 2)
        self.recipient_username_textbox.grid(row = 1, column = 0, padx = 20, pady = (10,20))
        self.submit_recipient_username.grid(row = 1, column = 1, padx = 20, pady = (10,20))

    def retrieveRecipientUsername(self):
        recipient = self.recipient_username_textbox.get()
        print(f"recipient is : {recipient}")
        hashed_recipient = hashlib.sha256(recipient.encode('utf-8')).hexdigest()

        response = (supabase.table('keys')
                         .select("hashed_user")
                         .eq("hashed_user",hashed_recipient)
                         .execute()
        )

        if response:
            if not response.data: #if hashed recipient doesn't exist
                print("Invalid recipient. Please check the spelling of your recipient.")
            else:
                print("Recipient is verified. Proceed with Encryption.")

class mainProgramFrame(customtkinter.CTkFrame):
    def __init__(self, master, switch_callback):
        super().__init__(master)

        self.switch_callback = switch_callback

        self.loadfile_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Load Text File", command=self.loadFile) #currently no command
        self.loadfile_button.grid(row = 0, column = 0, padx = 20, pady = 20)

        self.encrypt_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Encrypt a File", command=self.encrypt) #currently no command
        self.encrypt_button.grid(row = 0, column = 1, padx = 20, pady = 20)

        self.decrypt_button = customtkinter.CTkButton(self, width = 150, height = 20, text="Decrypt a File", command=self.decrypt) #currently no command
        self.decrypt_button.grid(row = 0, column = 2, padx = 20, pady = 20)
    
    def loadFile(self):
        print('user is loading file...')
        userfile = filedialog.askopenfilename() #userfile is the path to the file we want to encrypt
        print('user selected file: ', userfile)
    def encrypt(self):
        print('user chose to encrypt!')
        self.switch_callback() #reveal "enter recipient username" frame
    def decrypt(self):
        print('user chose to decrypt!')

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title('redwood84')
        self.geometry('800x640')
        self.grid_columnconfigure(0, weight=1)

        self.login_frame = loginFrame(self, self.show_main_frame)
        self.login_frame.grid(row=0, column=0, padx=20, pady=(200,0))

        self.mainprogram_frame = mainProgramFrame(self, self.show_recipient_frame)
        self.mainprogram_frame.grid(row = 0, column = 0, padx=20, pady=(200,0))
        self.mainprogram_frame.grid_forget()

        self.recipient_user_frame = recipientUsernameFrame(self)
        self.recipient_user_frame.grid(row = 0, column = 0, padx=20, pady=(200,0))
        self.recipient_user_frame.grid_forget()

    def show_main_frame(self):
        self.login_frame.grid_forget() #hide login panel
        self.mainprogram_frame.grid(row = 0, column = 0, padx=20, pady=(200,0)) #show main program frame
    
    def show_recipient_frame(self):
        self.recipient_user_frame.grid(row = 1, column = 0, padx=20, pady=(10,0)) #show recipient frame
        
app = App()
app.mainloop()