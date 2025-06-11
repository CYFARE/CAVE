# Compiler settings
# Note: These are the commands for the cross-compiler.
CPP_COMPILER = "x86_64-w64-mingw32-g++"
C_COMPILER = "x86_64-w64-mingw32-gcc"

# Common compiler flags
# -s: strip all symbols
# -O2: optimization level 2
# -mwindows: create a GUI application (no console window)
# -Wall: enable all warnings
COMPILER_FLAGS = "-O2 -s -mwindows -Wall"

# Default output directory
OUTPUT_DIR = "output/"

# Jinja2 template directories
TEMPLATE_DIRS = ["templates", "templates/cpp", "templates/vba"]