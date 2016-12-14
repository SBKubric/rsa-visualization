from tkinter import *
from threading import Thread
import time
import rsa


class RSAVisualizationUI(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        self.primes = None
        self.p = None
        self.q = None
        self.private = None
        self.public = None
        self.message = None
        self.cipher = None

        self.parent = master
        self.pack(fill=BOTH, expand=True)
        self.init_ui()

    def init_ui(self):
        self.image_user = PhotoImage(file='./images/user.gif')
        self.image_arrow = PhotoImage(file='./images/trending_flat.gif')
        self.image_security = PhotoImage(file='./images/security.gif')
        self.image_key = PhotoImage(file='./images/key.gif')
        self.primes = rsa.get_some_primes()
        self.p, self.q = rsa.get_rand_p_and_q(self.primes)
        self.public, self.private = rsa.generate_keypair(self.p, self.q)

        base_frame_top = Frame(self)

        frame_sender = Frame(base_frame_top)
        Label(frame_sender, image=self.image_user).grid(row=0, column=0)
        Label(frame_sender, text='Sender').grid(row=1, column=0)
        Label(frame_sender, text='Print your message here').grid(row=2, column=0)
        self.entry = Entry(frame_sender)
        self.entry.grid(row=3, column=0)
        self.entry.focus_set()
        self.entry.insert(0, 'Hello, RSA!')
        frame_sender.pack(side=LEFT, anchor=CENTER)

        self.frame_pub_k = Frame(base_frame_top)
        self.arrow_pub_k = Label(self.frame_pub_k, image=self.image_arrow)
        self.arrow_pub_k.grid(row=0, column=0)
        self.title_pub_k = Label(self.frame_pub_k, text='Public Key')
        self.title_pub_k.grid(row=1, column=0)
        self.text_pub_key = Label(self.frame_pub_k, text=str(self.public))
        self.text_pub_key.grid(row=2, column=0)
        self.key_pub_k = Label(self.frame_pub_k, image=self.image_key)
        self.key_pub_k.grid(row=3, column=0)
        self.frame_pub_k.pack(side=LEFT, anchor=CENTER)

        frame_security = Frame(base_frame_top)
        Label(frame_security, image=self.image_security).grid(row=0, column=0)
        Label(frame_security, text='Encrypted message').grid(row=1, column=0)
        self.text_cipher = Message(frame_security)
        self.text_cipher.grid(row=2, column=0)
        frame_security.pack(side=LEFT, anchor=CENTER)

        self.frame_pr_k = Frame(base_frame_top)
        self.arrow_pr_k = Label(self.frame_pr_k, image=self.image_arrow)
        self.arrow_pr_k.grid(row=0, column=0)
        self.title_pr_k = Label(self.frame_pr_k, text='Private Key')
        self.title_pr_k.grid(row=1, column=0)
        self.text_pr_key = Label(self.frame_pr_k, text=str(self.private))
        self.text_pr_key.grid(row=2, column=0)
        self.key_pr_k = Label(self.frame_pr_k, image=self.image_key)
        self.key_pr_k.grid(row=3, column=0)
        self.frame_pr_k.pack(side=LEFT, anchor=CENTER)

        frame_receiver = Frame(base_frame_top)
        Label(frame_receiver, image=self.image_user).grid(row=0, column=0)
        Label(frame_receiver, text='Receiver').grid(row=1, column=0)
        Label(frame_receiver, text='Decrypted Message').grid(row=2, column=0)
        self.text_decrypted = Message(frame_receiver, text='Hello, RSA!')
        self.text_decrypted.grid(row=3, column=0)
        frame_receiver.pack(side=LEFT, anchor=CENTER)

        self.btn_start = Button(base_frame_top, text='Start', command=self.start_emulation)
        self.btn_start.pack(side=TOP, anchor=E)
        base_frame_top.pack(side=TOP, fill=X, expand=True)

        base_frame_bottom = Frame(self)
        self.btn_send = Button(self, text='Send', state='disabled', command=self.send_message)
        self.btn_send.pack(side=LEFT, anchor=SW)
        self.btn_finish = Button(self, text='Finish', state='disabled', command=self.finish_transition)
        self.btn_finish.pack(side=LEFT, anchor=SW)
        self.process_line = Label(base_frame_bottom, text='Go, press the "Start" button!')
        self.process_line.pack(side=LEFT, padx=20, anchor=CENTER)
        Button(base_frame_bottom, text='Close', command=self.master.destroy).pack(side=RIGHT, anchor=SE)
        base_frame_bottom.pack(side=TOP, fill=X, expand=True)
        self.after(10, self.set_ui)


    def set_ui_thread(self):
        self.arrow_pr_k.grid_remove()
        self.title_pr_k.grid_remove()
        self.text_pr_key.grid_remove()
        self.key_pr_k.grid_remove()

        self.arrow_pub_k.grid_remove()
        self.title_pub_k.grid_remove()
        self.text_pub_key.grid_remove()
        self.key_pub_k.grid_remove()

    def generate_keys_thread(self):
        self.primes = rsa.get_some_primes()
        self.p, self.q = rsa.get_rand_p_and_q(self.primes)
        self.process_line.configure(text='Generating your public/private keypairs now . . .')
        time.sleep(2)
        self.public, self.private = rsa.generate_keypair(self.p, self.q)
        self.text_pr_key.configure(text=str(self.private))
        self.text_pub_key.configure(text=str(self.public))
        self.process_line.configure(text='Enter a message to encrypt with your public key and press the "Send" button')
        time.sleep(1)
        self.btn_send['state'] = 'normal'

    def set_ui(self):
        thread = Thread(target=self.set_ui_thread)
        thread.start()

    def start_emulation(self):
        thread = Thread(target=self.generate_keys_thread)
        self.btn_start['state'] = 'disabled'
        thread.start()

    def send_message_thread(self):
        self.message = self.entry.get()
        time.sleep(1)
        self.process_line.configure(text='Encrypting...')
        self.arrow_pub_k.grid()
        self.title_pub_k.grid()
        self.text_pub_key.grid()
        self.key_pub_k.grid()
        self.cipher = rsa.encrypt(self.public, self.message)
        time.sleep(2)
        self.process_line.configure(text='Done encrypting!')
        self.text_cipher.configure(text=rsa.get_encrypted_str(self.cipher))
        time.sleep(1)
        self.process_line.configure(text='Sending...')
        self.arrow_pr_k.grid()
        self.title_pr_k.grid()
        self.text_pr_key.grid()
        self.key_pr_k.grid()
        time.sleep(1)
        self.process_line.configure(text='Decrypting...')
        self.message = rsa.decrypt(self.private, self.cipher)
        time.sleep(3)
        self.process_line.configure(text='Done!')
        self.text_decrypted.configure(text=self.message)
        time.sleep(1)
        self.btn_send['state'] = 'normal'

    def send_message(self):
        thread = Thread(target=self.send_message_thread)
        self.btn_send['state'] = 'disabled'
        self.btn_finish['state'] = 'normal'
        thread.start()

    def finish_transition(self):
        self.btn_send['state'] = 'disabled'
        self.btn_finish['state'] = 'disabled'
        self.btn_start['state'] = 'normal'
        self.set_ui()




class MainMenu(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        self.master = master
        self.pack(fill=BOTH, expand=True)
        # self.center_window()
        self.init_ui()

    def start_rsa_enc_vis(self):
        rsa_window = Toplevel(self.master)
        rsa_app = RSAVisualizationUI(rsa_window)

    def start_terminal_mode(self):
        rsa.terminal_mode()

    def center_window(self):
        w = self.master.winfo_screenwidth()
        h = self.master.winfo_screenheight()
        size = tuple(int(_) for _ in self.master.geometry().split('+')[0].split('x'))
        x = w/2 - size[0]/2
        y = h/2 - size[1]/2
        self.master.geometry("%dx%d+%d+%d" % (size[0], size[1], x, y))

    def init_ui(self):
        self.master.title('RSA Algorithm Visualization')
        self.image_label = PhotoImage(file='./images/RSA-Encryption.gif')
        Label(self, image=self.image_label).pack(side=TOP, anchor=N)

        frame_rsa_enc_vis = Frame(self)
        Label(frame_rsa_enc_vis, text='RSA Encryption Visualization', background='grey').pack(side=LEFT, fill=X, expand=True, anchor=W)
        Button(frame_rsa_enc_vis, text='Start', command=self.start_rsa_enc_vis).pack(side=LEFT, anchor=E, padx=5)
        frame_rsa_enc_vis.pack(side=TOP, fill=X, expand=True, padx=5, pady=5)

        frame_terminal_mode = Frame(self)
        Label(frame_terminal_mode, text='Terminal Mode', background='grey').pack(side=LEFT, fill=X, expand=True, anchor=W)
        Button(frame_terminal_mode, text='Start', command=self.start_terminal_mode).pack(side=LEFT, anchor=E, padx=5)
        frame_terminal_mode.pack(side=TOP, fill=X, expand=True, padx=5, pady=5)

        Button(self, text='Quit', command=self.quit).pack(side=TOP, anchor=CENTER, padx=5, pady=5)





def main():
    root = Tk()
    ui = MainMenu(root)
    root.geometry("480x400+300+300")
    root.mainloop()


if __name__ == '__main__':
    main()
