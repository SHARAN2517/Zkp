#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for ZKP IoT Authentication System
Tests all endpoints including device registration, authentication, sensor data, and security features.
"""

import requests
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Any

class ZKPIoTAPITester:
    def __init__(self, base_url="https://secureiot-sim.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.created_device_ids = []
        
        # Test session
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})

    def log_test(self, name: str, success: bool, details: str = ""):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED {details}")
        else:
            print(f"❌ {name} - FAILED {details}")
        return success

    def make_request(self, method: str, endpoint: str, data: Dict = None, params: Dict = None) -> tuple:
        """Make HTTP request and return (success, response_data, status_code)"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, params=params)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, params=params)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, params=params)
            else:
                return False, {}, 0
                
            return response.status_code < 400, response.json() if response.content else {}, response.status_code
            
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return False, {}, 0
        except json.JSONDecodeError:
            return response.status_code < 400, {}, response.status_code

    def test_api_root(self):
        """Test API root endpoint"""
        success, data, status = self.make_request('GET', '/')
        return self.log_test(
            "API Root Endpoint", 
            success and status == 200,
            f"Status: {status}, Message: {data.get('message', 'N/A')}"
        )

    def test_device_registration(self):
        """Test device registration endpoint"""
        test_devices = [
            {
                "device_name": "Test Smart Thermostat",
                "device_type": "smart_home",
                "manufacturer": "TestCorp",
                "mac_address": "AA:BB:CC:DD:EE:01",
                "location": "Test Living Room"
            },
            {
                "device_name": "Test Heart Monitor",
                "device_type": "healthcare", 
                "manufacturer": "HealthTech",
                "mac_address": "AA:BB:CC:DD:EE:02",
                "location": "Test Bedroom"
            },
            {
                "device_name": "Test Industrial Sensor",
                "device_type": "industrial",
                "manufacturer": "IndustrialCorp",
                "mac_address": "AA:BB:CC:DD:EE:03", 
                "location": "Test Factory Floor"
            }
        ]
        
        all_passed = True
        for i, device_data in enumerate(test_devices):
            success, response_data, status = self.make_request('POST', '/devices', device_data)
            
            if success and status == 200:
                device_id = response_data.get('id')
                if device_id:
                    self.created_device_ids.append(device_id)
                    
                # Verify required fields in response
                required_fields = ['id', 'device_name', 'device_type', 'zkp_identity_hash', 'status']
                missing_fields = [field for field in required_fields if field not in response_data]
                
                test_passed = len(missing_fields) == 0 and response_data.get('status') == 'online'
                self.log_test(
                    f"Device Registration #{i+1} ({device_data['device_type']})",
                    test_passed,
                    f"ID: {device_id[:8]}..., Status: {response_data.get('status')}, Missing: {missing_fields}"
                )
                all_passed = all_passed and test_passed
            else:
                self.log_test(
                    f"Device Registration #{i+1} ({device_data['device_type']})",
                    False,
                    f"Status: {status}, Response: {response_data}"
                )
                all_passed = False
                
        return all_passed

    def test_get_devices(self):
        """Test getting all devices"""
        success, data, status = self.make_request('GET', '/devices')
        
        if success and status == 200:
            devices = data if isinstance(data, list) else []
            # Should include our test devices plus existing ones
            test_passed = len(devices) >= len(self.created_device_ids)
            return self.log_test(
                "Get All Devices",
                test_passed,
                f"Found {len(devices)} devices, Expected at least {len(self.created_device_ids)}"
            )
        else:
            return self.log_test("Get All Devices", False, f"Status: {status}")

    def test_device_authentication(self):
        """Test device authentication with both ZKP and traditional methods"""
        if not self.created_device_ids:
            return self.log_test("Device Authentication", False, "No devices to test authentication")
        
        all_passed = True
        
        for device_id in self.created_device_ids[:2]:  # Test first 2 devices
            # Test ZKP Authentication
            success, data, status = self.make_request('POST', f'/authenticate/{device_id}', params={'auth_method': 'zero_knowledge'})
            
            if success and status == 200:
                zkp_passed = (
                    data.get('success') == True and 
                    data.get('auth_method') == 'zero_knowledge' and
                    data.get('privacy_preserved') == True
                )
                self.log_test(
                    f"ZKP Authentication ({device_id[:8]}...)",
                    zkp_passed,
                    f"Success: {data.get('success')}, Privacy: {data.get('privacy_preserved')}"
                )
                all_passed = all_passed and zkp_passed
            else:
                self.log_test(f"ZKP Authentication ({device_id[:8]}...)", False, f"Status: {status}")
                all_passed = False
            
            # Test Traditional Authentication
            success, data, status = self.make_request('POST', f'/authenticate/{device_id}', params={'auth_method': 'traditional'})
            
            if success and status == 200:
                trad_passed = (
                    data.get('success') == True and 
                    data.get('auth_method') == 'traditional' and
                    data.get('privacy_preserved') == False
                )
                self.log_test(
                    f"Traditional Authentication ({device_id[:8]}...)",
                    trad_passed,
                    f"Success: {data.get('success')}, Privacy: {data.get('privacy_preserved')}"
                )
                all_passed = all_passed and trad_passed
            else:
                self.log_test(f"Traditional Authentication ({device_id[:8]}...)", False, f"Status: {status}")
                all_passed = False
                
        return all_passed

    def test_sensor_readings(self):
        """Test sensor data retrieval endpoints"""
        # Wait a bit for IoT simulation to generate some data
        print("⏳ Waiting 15 seconds for IoT simulation to generate sensor data...")
        time.sleep(15)
        
        all_passed = True
        
        # Test get all sensor readings
        success, data, status = self.make_request('GET', '/sensor-readings', params={'limit': 50})
        
        if success and status == 200:
            readings = data if isinstance(data, list) else []
            
            # Check if we have sensor readings
            has_readings = len(readings) > 0
            self.log_test(
                "Get All Sensor Readings",
                has_readings,
                f"Found {len(readings)} sensor readings"
            )
            all_passed = all_passed and has_readings
            
            # Verify sensor reading structure
            if readings:
                sample_reading = readings[0]
                required_fields = ['id', 'device_id', 'sensor_type', 'value', 'unit', 'timestamp', 'is_privacy_sensitive']
                missing_fields = [field for field in required_fields if field not in sample_reading]
                
                structure_valid = len(missing_fields) == 0
                self.log_test(
                    "Sensor Reading Structure",
                    structure_valid,
                    f"Missing fields: {missing_fields}" if missing_fields else "All required fields present"
                )
                all_passed = all_passed and structure_valid
                
                # Check for privacy-sensitive data (heart rate)
                privacy_sensitive = [r for r in readings if r.get('is_privacy_sensitive', False)]
                heart_rate_readings = [r for r in readings if r.get('sensor_type') == 'heart_rate']
                
                privacy_check = len(heart_rate_readings) == 0 or len(privacy_sensitive) > 0
                self.log_test(
                    "Privacy-Sensitive Data Marking",
                    privacy_check,
                    f"Heart rate readings: {len(heart_rate_readings)}, Privacy-sensitive: {len(privacy_sensitive)}"
                )
                all_passed = all_passed and privacy_check
        else:
            self.log_test("Get All Sensor Readings", False, f"Status: {status}")
            all_passed = False
            
        # Test device-specific sensor readings
        if self.created_device_ids:
            device_id = self.created_device_ids[0]
            success, data, status = self.make_request('GET', f'/sensor-readings/{device_id}', params={'limit': 20})
            
            device_readings_passed = success and status == 200
            self.log_test(
                f"Device Sensor Readings ({device_id[:8]}...)",
                device_readings_passed,
                f"Status: {status}, Readings: {len(data) if isinstance(data, list) else 0}"
            )
            all_passed = all_passed and device_readings_passed
            
        return all_passed

    def test_dashboard_stats(self):
        """Test dashboard statistics endpoint"""
        success, data, status = self.make_request('GET', '/dashboard-stats')
        
        if success and status == 200:
            required_fields = [
                'total_devices', 'online_devices', 'successful_auths_today', 
                'failed_auths_today', 'avg_privacy_score', 'threat_level',
                'total_sensor_readings', 'privacy_sensitive_readings'
            ]
            
            missing_fields = [field for field in required_fields if field not in data]
            
            # Validate data types and ranges
            valid_data = True
            validation_errors = []
            
            if 'total_devices' in data and not isinstance(data['total_devices'], int):
                validation_errors.append("total_devices not integer")
                valid_data = False
                
            if 'avg_privacy_score' in data and not (0 <= data.get('avg_privacy_score', 0) <= 100):
                validation_errors.append("avg_privacy_score not in 0-100 range")
                valid_data = False
                
            if 'threat_level' in data and data['threat_level'] not in ['low', 'medium', 'high', 'critical']:
                validation_errors.append("invalid threat_level")
                valid_data = False
            
            stats_passed = len(missing_fields) == 0 and valid_data
            return self.log_test(
                "Dashboard Statistics",
                stats_passed,
                f"Missing: {missing_fields}, Validation errors: {validation_errors}, Devices: {data.get('total_devices', 0)}"
            )
        else:
            return self.log_test("Dashboard Statistics", False, f"Status: {status}")

    def test_authentication_logs(self):
        """Test authentication logs endpoint"""
        success, data, status = self.make_request('GET', '/authentication-logs')
        
        if success and status == 200:
            logs = data if isinstance(data, list) else []
            
            # Should have logs from our authentication tests
            has_logs = len(logs) > 0
            self.log_test(
                "Authentication Logs",
                has_logs,
                f"Found {len(logs)} authentication logs"
            )
            
            # Verify log structure
            if logs:
                sample_log = logs[0]
                required_fields = ['id', 'device_id', 'device_name', 'auth_method', 'success', 'timestamp', 'privacy_preserved']
                missing_fields = [field for field in required_fields if field not in sample_log]
                
                structure_valid = len(missing_fields) == 0
                self.log_test(
                    "Auth Log Structure",
                    structure_valid,
                    f"Missing fields: {missing_fields}" if missing_fields else "All required fields present"
                )
                return has_logs and structure_valid
            
            return has_logs
        else:
            return self.log_test("Authentication Logs", False, f"Status: {status}")

    def test_security_events(self):
        """Test security events endpoint"""
        success, data, status = self.make_request('GET', '/security-events')
        
        if success and status == 200:
            events = data if isinstance(data, list) else []
            
            # Should have at least device registration events
            has_events = len(events) > 0
            return self.log_test(
                "Security Events",
                has_events,
                f"Found {len(events)} security events"
            )
        else:
            return self.log_test("Security Events", False, f"Status: {status}")

    def test_threat_simulation(self):
        """Test threat simulation endpoint"""
        success, data, status = self.make_request('GET', '/simulate-threat')
        
        if success and status == 200:
            threat_created = 'event' in data and 'message' in data
            return self.log_test(
                "Threat Simulation",
                threat_created,
                f"Message: {data.get('message', 'N/A')}"
            )
        else:
            return self.log_test("Threat Simulation", False, f"Status: {status}")

    def test_existing_sample_devices(self):
        """Test authentication with existing sample devices mentioned in the request"""
        sample_device_ids = [
            "b406e5f1-0522-406d-b047-b1947ee08c14",  # Smart Thermostat
            "79138b1d-223a-4938-874a-e5cad53c9c00",  # Heart Rate Monitor  
            "1b7b132d-9484-4a09-beca-c0cf33aaf937"   # Industrial Temperature Sensor
        ]
        
        all_passed = True
        
        for device_id in sample_device_ids:
            # Test ZKP authentication on existing devices
            success, data, status = self.make_request('POST', f'/authenticate/{device_id}', params={'auth_method': 'zero_knowledge'})
            
            if success and status == 200:
                auth_passed = data.get('success') == True and data.get('privacy_preserved') == True
                self.log_test(
                    f"Sample Device Auth ({device_id[:8]}...)",
                    auth_passed,
                    f"Success: {data.get('success')}, Privacy: {data.get('privacy_preserved')}"
                )
                all_passed = all_passed and auth_passed
            else:
                self.log_test(f"Sample Device Auth ({device_id[:8]}...)", False, f"Status: {status}")
                all_passed = False
                
        return all_passed

    def run_all_tests(self):
        """Run comprehensive API test suite"""
        print("🚀 Starting ZKP IoT Authentication System API Tests")
        print(f"🔗 Testing API at: {self.base_url}")
        print("=" * 80)
        
        # Core API Tests
        self.test_api_root()
        self.test_device_registration()
        self.test_get_devices()
        self.test_device_authentication()
        
        # Data and Analytics Tests
        self.test_sensor_readings()
        self.test_dashboard_stats()
        self.test_authentication_logs()
        self.test_security_events()
        
        # Security Tests
        self.test_threat_simulation()
        self.test_existing_sample_devices()
        
        # Print Results
        print("=" * 80)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests PASSED! Backend API is working correctly.")
            return 0
        else:
            failed_tests = self.tests_run - self.tests_passed
            print(f"⚠️  {failed_tests} test(s) FAILED. Please check the issues above.")
            return 1

def main():
    """Main test execution"""
    tester = ZKPIoTAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())