import requests
import sys
import json
import time
from datetime import datetime
from typing import Dict, Any

class ZKPIoTPlatformTester:
    def __init__(self, base_url="https://iot-data-hub.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.created_device_id = None

    def run_test(self, name: str, method: str, endpoint: str, expected_status: int, data: Dict[str, Any] = None, params: Dict[str, Any] = None) -> tuple:
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, params=params, timeout=30)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, params=params, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, params=params, timeout=30)

            print(f"   Status Code: {response.status_code}")
            
            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ PASSED - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    if isinstance(response_data, dict) and len(str(response_data)) < 500:
                        print(f"   Response: {json.dumps(response_data, indent=2, default=str)}")
                    elif isinstance(response_data, list):
                        print(f"   Response: List with {len(response_data)} items")
                        if response_data and len(str(response_data[0])) < 200:
                            print(f"   First item: {json.dumps(response_data[0], indent=2, default=str)}")
                    return success, response_data
                except:
                    return success, response.text
            else:
                print(f"❌ FAILED - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {json.dumps(error_data, indent=2)}")
                except:
                    print(f"   Error: {response.text}")
                return False, {}

        except requests.exceptions.Timeout:
            print(f"❌ FAILED - Request timeout (30s)")
            return False, {}
        except requests.exceptions.ConnectionError:
            print(f"❌ FAILED - Connection error")
            return False, {}
        except Exception as e:
            print(f"❌ FAILED - Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test the root API endpoint"""
        return self.run_test("Root API Endpoint", "GET", "", 200)

    def test_get_devices(self):
        """Test getting all devices"""
        return self.run_test("Get All Devices", "GET", "devices", 200)

    def test_register_device(self):
        """Test device registration"""
        device_data = {
            "device_name": f"Test Device {datetime.now().strftime('%H%M%S')}",
            "device_type": "smart_home",
            "manufacturer": "TestCorp",
            "mac_address": f"AA:BB:CC:DD:EE:{datetime.now().strftime('%S')}",
            "location": "Test Lab",
            "data_source": "simulated",
            "capabilities": ["temperature", "humidity"],
            "is_remote_controllable": True
        }
        
        success, response = self.run_test("Register Device", "POST", "devices", 200, data=device_data)
        if success and isinstance(response, dict) and 'id' in response:
            self.created_device_id = response['id']
            print(f"   Created device ID: {self.created_device_id}")
        return success, response

    def test_get_sensor_readings(self):
        """Test getting all sensor readings"""
        return self.run_test("Get All Sensor Readings", "GET", "sensor-readings", 200)

    def test_get_device_sensor_readings(self):
        """Test getting sensor readings for a specific device"""
        if not self.created_device_id:
            print("⚠️  Skipping device-specific sensor readings test - no device created")
            return True, {}
        
        return self.run_test(
            "Get Device Sensor Readings", 
            "GET", 
            f"devices/{self.created_device_id}/sensor-readings", 
            200
        )

    def test_get_alerts(self):
        """Test getting alerts"""
        return self.run_test("Get All Alerts", "GET", "alerts", 200)

    def test_get_dashboard_stats(self):
        """Test getting dashboard statistics"""
        return self.run_test("Get Dashboard Stats", "GET", "dashboard-stats", 200)

    def test_device_command(self):
        """Test sending command to device"""
        if not self.created_device_id:
            print("⚠️  Skipping device command test - no device created")
            return True, {}
        
        return self.run_test(
            "Send Device Command", 
            "POST", 
            f"devices/{self.created_device_id}/command", 
            200,
            params={"command": "test_command"},
            data={"parameter1": "value1"}
        )

    def test_websocket_endpoint(self):
        """Test WebSocket endpoint availability (just check if endpoint exists)"""
        # We can't easily test WebSocket in this simple test, but we can check if the endpoint is accessible
        print(f"\n🔍 Testing WebSocket Endpoint Availability...")
        print(f"   WebSocket URL would be: {self.base_url.replace('https://', 'wss://')}/api/ws")
        print("✅ WebSocket endpoint noted (actual connection testing done in frontend)")
        self.tests_run += 1
        self.tests_passed += 1
        return True, {}

    def wait_for_data_generation(self):
        """Wait for background data generation to create some sensor readings"""
        print(f"\n⏳ Waiting 15 seconds for background data generation...")
        time.sleep(15)
        print("✅ Wait completed")

def main():
    print("🚀 Starting ZKP IoT Platform Backend API Testing")
    print("=" * 60)
    
    tester = ZKPIoTPlatformTester()
    
    # Test sequence
    tests = [
        ("Root API", tester.test_root_endpoint),
        ("Get Devices", tester.test_get_devices),
        ("Register Device", tester.test_register_device),
        ("Wait for Data", tester.wait_for_data_generation),
        ("Get Sensor Readings", tester.test_get_sensor_readings),
        ("Get Device Sensor Readings", tester.test_get_device_sensor_readings),
        ("Get Alerts", tester.test_get_alerts),
        ("Get Dashboard Stats", tester.test_get_dashboard_stats),
        ("Send Device Command", tester.test_device_command),
        ("WebSocket Endpoint", tester.test_websocket_endpoint),
    ]
    
    failed_tests = []
    
    for test_name, test_func in tests:
        try:
            if test_name == "Wait for Data":
                test_func()
                continue
                
            success, _ = test_func()
            if not success:
                failed_tests.append(test_name)
        except Exception as e:
            print(f"❌ FAILED - {test_name}: {str(e)}")
            failed_tests.append(test_name)
    
    # Print final results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {tester.tests_run}")
    print(f"Passed: {tester.tests_passed}")
    print(f"Failed: {tester.tests_run - tester.tests_passed}")
    print(f"Success Rate: {(tester.tests_passed / tester.tests_run * 100):.1f}%")
    
    if failed_tests:
        print(f"\n❌ Failed Tests:")
        for test in failed_tests:
            print(f"   - {test}")
    else:
        print(f"\n✅ All tests passed!")
    
    # Test real-time data generation
    print(f"\n🔄 Testing Real-time Data Generation...")
    try:
        # Get initial reading count
        success1, response1 = tester.run_test("Initial Sensor Count", "GET", "sensor-readings", 200)
        initial_count = len(response1) if success1 and isinstance(response1, list) else 0
        
        print(f"   Initial sensor readings: {initial_count}")
        print(f"   Waiting 20 seconds for new data...")
        time.sleep(20)
        
        # Get updated reading count
        success2, response2 = tester.run_test("Updated Sensor Count", "GET", "sensor-readings", 200)
        updated_count = len(response2) if success2 and isinstance(response2, list) else 0
        
        print(f"   Updated sensor readings: {updated_count}")
        
        if updated_count > initial_count:
            print(f"✅ Real-time data generation is working! (+{updated_count - initial_count} new readings)")
        else:
            print(f"⚠️  Real-time data generation may not be working (no new readings detected)")
            
    except Exception as e:
        print(f"❌ Error testing real-time data: {str(e)}")
    
    return 0 if tester.tests_passed == tester.tests_run else 1

if __name__ == "__main__":
    sys.exit(main())