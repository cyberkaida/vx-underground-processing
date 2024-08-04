import os

import ghidra
from ghidra.framework.options import Options
from ghidra.program.model.listing import Program

assert currentProgram is not None, "This script needs a program!"

options = currentProgram.getOptions(Program.PROGRAM_INFO)

# Now we get the CART metadata for this file
VX_FAMILY = os.getenv("VX_FAMILY")
VX_DATE = os.getenv("VX_DATE")
VX_URL = os.getenv("VX_URL")
options.setString("source", "VX-Underground")
assert VX_FAMILY, "VX_FAMILY environment variable must be set!"
options.setString("family", VX_FAMILY)
if VX_URL:
    options.setString("source_url", VX_URL)
if VX_DATE:
    options.setString("date", VX_DATE)