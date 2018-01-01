# ExtractPESections

Extracting a PE file's each sections and create new dump file.

The extracted files have the following order.

- 00_HEADER
- 01_(section_name).section
- 02_(section_name).section
- ...
- 0n_(section_name).section
- 0n+1_EXTRASECTION


USAGE: ExtractPeSections.exe [toExtractPEFile]

