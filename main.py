import base64
import datetime
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from tkinter import *
import tkinter.messagebox
import tkinter.font as font

FinalN = '$2b$12$0hggGaeF8p3/IjqYJpxqie2WAWZW1BwgvuJ9i3uH5j26xWe91fSZm'.encode()  # it is (Amer)
FinalP = '$2b$12$vtM0o/3EtVEKI22E5AlfJOEr4gkT0yBUoN0MwmzvfGQOCDtIA00qG'.encode()  # it is (Mosally)

###############
Path = 'Vault.txt'
name = None
password = None
flag = False

def file_path():
    window = Tk()
    window.title(' PATH ')
    f = Frame(window)
    window.geometry("480x180")
    label5 = Label(window,
                   text="Enter the full path of your text file, for example ( C:/Users/Desktop/Vault.txt ).").place(
        x=35, y=50)
    entry5 = Entry(window)
    entry5.place(x=60, y=80, width=350, height=30)

    def temp():
        global Path
        Path = entry1.get()

    button5 = Button(window, text='  Enter  ', fg='snow', bg='RoyalBlue3',
                     command=lambda: [temp(), window.destroy()]).place(x=210, y=120, width=60, height=35)
    f.pack()
    window.mainloop()


def exit():
    i = tkinter.messagebox.askyesno(title='Exit', message='Are you sure you want to exit?')
    if i:
        sys.exit(0)


root1 = Tk()
root1.geometry("390x255")
root1.title(' Vault ')
frame = Frame(root1)

fontStyle = font.Font(family='Informal Roman', size=25)
label = Label(root1, text='ORIA', font=fontStyle).place(x=170, y=0)

label1 = Label(root1, text='Username:').place(x=60, y=50)
label2 = Label(root1, text='Password:').place(x=60, y=87)
entry1 = Entry(root1)
entry1.place(x=150, y=50)
entry2 = Entry(root1)
entry2.place(x=150, y=90)

c = Checkbutton(root1, text='Keep log in (just kidding won\'t work, Don\'t be lazy)  :)').place(x=90, y=155)


# ***** Main menu *****
def menu(root, y):
    menus = Menu(root)
    root.config(menu=menus)

    subMenu = Menu(menus)
    menus.add_cascade(label="File", menu=subMenu)
    subMenu.add_command(label='New vault path', command=file_path)
    subMenu.add_command(label='What should i put here hmmmm! ', command=root.quit)  ##################
    subMenu.add_separator()
    subMenu.add_command(label='Exit', command=exit)

    editMenu = Menu(menus)
    menus.add_cascade(label="Help", menu=editMenu)

    def Info():
        tkinter.messagebox.showinfo('Info',
                                    'This program is Passwords vault and it use hash and salt to protect your password, every password you enter it has time stamp.\n\nMade using (PYTHON & tkinter)')
    editMenu.add_command(label="Info", command=Info)

    def copy():
        tkinter.messagebox.showinfo('Email', 'The email is copied to your clipboard :) ')
    editMenu.add_command(label="musalli.amer@gmail.com", command=copy)

    # ***** Status Bar *****
    status = Label(root, text=" Copy Right to Amer Mosally \t\t\t\t\t", bd=1, relief=SUNKEN, anchor=E).place(x=0, y=y,
                                                                                                             width=390,
                                                                                                             anchor=SW)

menu(root1, 255)
choice: int = 0
###############
def path(choice):
    if choice == 1:
        encrypt()
    elif choice == 2:
        decrypt()
    else:
        tkinter.messagebox.showinfo(title='Error', message='Invalid choice')

def encrypt():
    global Path

    def line():
        webName = entry31.get()
        userName = entry32.get()
        passwords = entry33.get()

        line = str(webName) + ',\n \t\t The username: ' + str(userName) + ',\t\t The password is: ' + str(passwords)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=bcrypt.gensalt(), iterations=100000,
                         backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        encrypted = f.encrypt(line.encode())
        file = open(Path, 'a')
        file.write(str(encrypted.decode()) + ' ' + str(key.decode()) + ' ' + str(datetime.datetime.now()))
        file.write('\n')
        file.close()

    root3 = Tk()
    root3.geometry("390x255")
    root3.title(' Vault ')
    frame3 = Frame(root3)
    menu(root3, 255)

    label1 = Label(root3, text='Website:', font=fontStyle).place(x=20, y=40)
    label2 = Label(root3, text='Username:', font=fontStyle).place(x=20, y=80)
    label3 = Label(root3, text='Password:', font=fontStyle).place(x=20, y=120)

    entry31 = Entry(root3)
    entry31.place(x=150, y=50)
    entry32 = Entry(root3)
    entry32.place(x=150, y=90)
    entry33 = Entry(root3)
    entry33.place(x=150, y=130)

    fontStyle1 = font.Font(family='Constantia', size=12)
    button1 = Button(root3, text='  Exit  ', fg='snow', bg='RoyalBlue3', font=fontStyle1, command=exit).place(x=10,y=200)
    button2 = Button(root3, text='  Return  ', fg='snow', bg='RoyalBlue3', font=fontStyle1, command=lambda: [root3.destroy(), main()]).place(x=70, y=200)
    button3 = Button(root3, text='  Enter  ', fg='snow', bg='RoyalBlue3', font=fontStyle1, command=lambda: [line()]).place(x=300, y=200)

    frame3.pack()
    root3.mainloop()
def decrypt():
    global Path
    root4 = Tk()

    scrollbar = Scrollbar(root4)
    scrollbar.pack(side=RIGHT, fill=Y)
    textbox = Text(root4)
    textbox.pack()

    root4.geometry("900x500")
    root4.title(' Vault ')
    frame4 = Frame(root4)
    menu(root4, 500)

    with open(Path, 'r') as file:
        x = file.read().split()
        for i in range(4, int(len(x)), 4):
            encrypted = x[i].encode()
            key = x[i + 1].encode()
            timeStamp = str(x[i + 2] + ' ' + x[i + 3])
            f = Fernet(key)
            decrypted = f.decrypt(encrypted).decode()
            text = Text(root4, width=900, height=500, wrap=NONE, xscrollcommand=scrollbar.set)
            textbox.insert(END, 'The web name: ' + str(decrypted) + ', \nat: ' + str(timeStamp) + '\n\n')

    fontStyle1 = font.Font(family='Constantia', size=12)
    button1 = Button(root4, text='  Exit  ', fg='snow', bg='RoyalBlue3', font=fontStyle1, command=exit).place(x=820, y=450)
    button2 = Button(root4, text='  Return  ', fg='snow', bg='RoyalBlue3', font=fontStyle, command=lambda: [root4.destroy(), main()]).place(x=740, y=450)

    frame4.pack()
    fontStyle2 = font.Font(family='Ubuntu', size=15)
    textbox.config(yscrollcommand=scrollbar.set, font=fontStyle2)
    scrollbar.config(command=textbox.yview)
    root4.mainloop()

#*******************#
def main():
    global choice
    global flag
    while choice != 3:
        if bcrypt.checkpw(name, FinalN) & bcrypt.checkpw(password, FinalP):
            if not flag:
                root1.destroy()
            flag = True
            root2 = Tk()
            root2.geometry("390x255")
            root2.title(' Vault ')
            frame2 = Frame(root2)
            menu(root2, 255)

            fontStyle1 = font.Font(family='Constantia', size=12)
            label1 = Label(root2, text='\nSelect your choice:', font=fontStyle).place(x=20, y=5)
            button1 = Button(root2, text='  Enter web password  ', fg='snow', bg='RoyalBlue3', font=fontStyle, command=lambda: [root2.destroy(), encrypt()]).place(x=50, y=100)
            button2 = Button(root2, text='  Read you passwords  ', fg='snow', bg='RoyalBlue3', font=fontStyle1, command=lambda: [root2.destroy(), decrypt()]).place(x=60, y=140)
            button3 = Button(root2, text='     Exit  \t', fg='snow', bg='RoyalBlue3', font=fontStyle1, command=exit).place(x=70, y=180)

            frame2.pack()
            root2.mainloop()
            try:
                choice = int(input())
                path(choice)
            except Exception:
                tkinter.messagebox.showinfo(title='Error', message='An error has occur')

        else:
            tkinter.messagebox.showinfo(title='Wrong',
                                        message='Username and Password didn\'t match Did you forgot the password or trying to hack ??? ')

            choice = 3
            entry1.delete(0, 'end')
            entry2.delete(0, 'end')
#*******************#
def button_initialize():
    global name
    global password
    global choice
    choice = 0
    name = entry1.get().encode()
    password = entry2.get().encode()
    main()

button1 = Button(root1, text='  Enter  ', fg='snow', bg='RoyalBlue3', command=button_initialize).place(x=320, y=195, width=60, height=35)
button2 = Button(root1, text='Forgot the password', fg='indian red', bg='grey75', command=lambda: [
    tkinter.messagebox.showinfo(title='Contact', message='Contact amer.mosally@gmail.com')]).place(x=150, y=120)
button3 = Button(root1, text='  Exit  ', fg='snow', bg='RoyalBlue2', command=exit).place(x=20, y=193, width=60, height=35, relheight=0.01, relwidth=0.01)

frame.pack()
root1.mainloop()