import pytest
import json
import tempfile
import os
from openvas_parser import convert_openvas_xml_to_json

def test_convert_openvas_xml_to_json():
    """Test basic XML to JSON conversion"""
    # Create a sample OpenVAS XML
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result id="test-result">
      <name>Test Vulnerability</name>
      <host>192.168.1.1</host>
      <port>80</port>
      <threat>High</threat>
      <severity>8.5</severity>
      <nvt>
        <name>Test NVT</name>
        <tags>summary=Test description|solution=Test solution</tags>
        <refs>
          <ref type="cve" id="CVE-2021-44228"/>
        </refs>
      </nvt>
    </result>
  </results>
</report>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as xml_file:
        xml_file.write(sample_xml)
        xml_path = xml_file.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as json_file:
        json_path = json_file.name
    
    try:
        # Test conversion
        result = convert_openvas_xml_to_json(xml_path, json_path)
        
        # Verify output
        assert os.path.exists(json_path)
        
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        assert 'report' in data
        assert 'results' in data['report']
        assert 'result' in data['report']['results']
        assert len(data['report']['results']['result']) == 1
        
        result_item = data['report']['results']['result'][0]
        assert result_item['cve'] == 'CVE-2021-44228'
        assert result_item['threat'] == 'High'
        assert result_item['severity'] == '8.5'
        
    finally:
        # Cleanup
        os.unlink(xml_path)
        os.unlink(json_path)

def test_no_cve_filtering():
    """Test that results without CVE are filtered out"""
    # Create XML with no CVE
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result id="test-result">
      <name>Test Vulnerability</name>
      <host>192.168.1.1</host>
      <port>80</port>
      <threat>High</threat>
      <severity>8.5</severity>
      <nvt>
        <name>Test NVT</name>
        <tags>summary=Test description|solution=Test solution</tags>
        <refs>
          <ref type="other" id="OTHER-123"/>
        </refs>
      </nvt>
    </result>
  </results>
</report>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as xml_file:
        xml_file.write(sample_xml)
        xml_path = xml_file.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as json_file:
        json_path = json_file.name
    
    try:
        # Test conversion
        result = convert_openvas_xml_to_json(xml_path, json_path)
        
        # Verify output
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        # Should be filtered out (no CVE)
        assert len(data['report']['results']['result']) == 0
        
    finally:
        # Cleanup
        os.unlink(xml_path)
        os.unlink(json_path)
