import sys
from cx_Freeze import setup, Executable

base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
    name="Your App",
    version="1.0",
    description="Description of your app",
    executables=[Executable("traffikcontrol.py", base=base)]
)
