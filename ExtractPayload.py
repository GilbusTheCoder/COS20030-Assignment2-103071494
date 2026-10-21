from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET
import hashlib

LAB_DIR = Path(r"C:\Users\student\MalwareSample\lab7")
SOURCE = LAB_DIR / "lab7_1.doc_"
OUTPUT = LAB_DIR / "stage2_extraction.bin"

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
with ZipFile(SOURCE, "r") as archive:
    xml_data = archive.read("word/document.xml")

root = ET.fromstring(xml_data)
payload = None


for textbox in root.iter(W + "txbxContent"):
    text = " ".join(
        element.text or ""
        for element in textbox.iter(W + "t"))
    
    values = text.split()

    if(len(values) >= 2 and values[:2] == ["77", "90"]):
        payload = bytes(int(value) for value in values)
        break


if payload is None:
    raise ValueError("Could not embedded executable payload...")
if payload[:2] != b"MZ":
    raise ValueError("Invalid DOS signature...")


peOffset = int.from_bytes(payload[0x3C:0x40], "little")
if payload[peOffset:peOffset + 4] != b"PE\x00\x00":
    raise ValueError("Invalid PE signature...")

OUTPUT.write_bytes(payload)

print(f"Payload Extracted:\n{OUTPUT}")
print(f"Size: {len(payload)} bytes")

for algorithm in ("md5", "sha1", "sha256"):
    digest = hashlib.new(algorithm, payload).hexdigest()
    print(f"{algorithm.upper()}:\t{digest}")