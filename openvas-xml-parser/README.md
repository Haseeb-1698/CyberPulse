# OpenVAS XML Parser

A Python library for converting OpenVAS XML scan reports to structured JSON format. This parser filters results to only include entries with CVE identifiers, making it easier to process and analyze vulnerability data.

## Features

- **XML to JSON Conversion**: Convert OpenVAS XML reports to structured JSON
- **CVE Filtering**: Only include results with CVE identifiers
- **Structured Output**: Clean, consistent JSON format
- **CLI Interface**: Command-line tool for batch processing
- **Minimal Dependencies**: Only requires `lxml` library

## Installation

```bash
pip install openvas-xml-parser
```

## Usage

### As a Python Library

```python
from openvas_parser import convert_openvas_xml_to_json

# Convert OpenVAS XML to JSON
convert_openvas_xml_to_json("scan_report.xml", "output.json")
```

### As a Command Line Tool

```bash
# Convert a single file
openvas-parser scan_report.xml output.json

# Convert multiple files
for file in *.xml; do
    openvas-parser "$file" "${file%.xml}.json"
done
```

## Output Format

The parser extracts the following information for each vulnerability:

```json
{
  "report": {
    "results": {
      "result": [
        {
          "result_id": "result-id",
          "result_name": "Vulnerability Name",
          "host": {"ip": "192.168.1.1"},
          "port": "80",
          "threat": "High",
          "severity": "8.5",
          "cve": "CVE-2021-44228",
          "additional_cves": ["CVE-2021-45046"],
          "description": "Vulnerability description",
          "nvt": {
            "name": "NVT Name",
            "description": "Detailed description",
            "solution": {"text": "Remediation steps"},
            "refs": {"ref": [{"type": "cve", "id": "CVE-2021-44228"}]}
          }
        }
      ]
    }
  }
}
```

## API Reference

### `convert_openvas_xml_to_json(xml_path, json_path)`

Convert an OpenVAS XML report to JSON format.

**Parameters:**
- `xml_path` (str): Path to the OpenVAS XML file
- `json_path` (str): Path where the JSON output will be saved

**Returns:**
- `str`: Path to the generated JSON file

**Raises:**
- `FileNotFoundError`: If the XML file doesn't exist
- `ET.ParseError`: If the XML file is malformed

## Examples

### Basic Usage

```python
from openvas_parser import convert_openvas_xml_to_json

try:
    result = convert_openvas_xml_to_json("scan.xml", "output.json")
    print(f"Conversion successful: {result}")
except Exception as e:
    print(f"Conversion failed: {e}")
```

### Batch Processing

```python
import os
from openvas_parser import convert_openvas_xml_to_json

xml_files = [f for f in os.listdir(".") if f.endswith(".xml")]

for xml_file in xml_files:
    json_file = xml_file.replace(".xml", ".json")
    try:
        convert_openvas_xml_to_json(xml_file, json_file)
        print(f"Converted {xml_file} to {json_file}")
    except Exception as e:
        print(f"Failed to convert {xml_file}: {e}")
```

## Development

### Setup Development Environment

```bash
git clone https://github.com/yourusername/openvas-xml-parser.git
cd openvas-xml-parser
pip install -e .
```

### Running Tests

```bash
python -m pytest tests/
```

### Building Distribution

```bash
python setup.py sdist bdist_wheel
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OpenVAS project for the XML format specification
- Advanced Vulnerability Management System for the original implementation

## Changelog

### 1.0.0
- Initial release
- XML to JSON conversion
- CVE filtering
- CLI interface
