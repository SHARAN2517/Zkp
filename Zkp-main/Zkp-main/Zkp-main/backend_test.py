import requests
import sys
import json
from datetime import datetime
import time

class ZKPIoTAPITester:
    def __init__(self, base_url="https://zkblock-iot.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.created_devices = []

    def run_test(self, name, method, endpoint, expected_status, data=None, params=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, params=params)

            print(f"   Status Code: {response.status_code}")
            
            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    if isinstance(response_data, dict) and len(str(response_data)) < 500:
                        print(f"   Response: {response_data}")
                    elif isinstance(response_data, list):
                        print(f"   Response: List with {len(response_data)} items")
                    return True, response_data
                except:
                    return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Error: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root API Endpoint", "GET", "", 200)

    def test_register_device(self, device_data):
        """Test device registration"""
        success, response = self.run_test(
            f"Register Device - {device_data['device_name']}", 
            "POST", 
            "devices", 
            200, 
            data=device_data
        )
        if success and 'id' in response:
            self.created_devices.append(response)
            return response['id']
        return None

    def test_get_devices(self):
        """Test getting all devices"""
        return self.run_test("Get All Devices", "GET", "devices", 200)

    def test_authenticate_device(self, device_id, auth_method="zero_knowledge"):
        """Test device authentication"""
        return self.run_test(
            f"Authenticate Device ({auth_method})", 
            "POST", 
            f"authenticate/{device_id}", 
            200,
            params={"auth_method": auth_method}
        )

    def test_get_auth_logs(self):
        """Test getting authentication logs"""
        return self.run_test("Get Authentication Logs", "GET", "authentication-logs", 200)

    def test_get_security_events(self):
        """Test getting security events"""
        return self.run_test("Get Security Events", "GET", "security-events", 200)

    def test_get_dashboard_stats(self):
        """Test getting dashboard statistics"""
        return self.run_test("Get Dashboard Stats", "GET", "dashboard-stats", 200)

    def test_simulate_threat(self):
        """Test threat simulation"""
        return self.run_test("Simulate Threat", "GET", "simulate-threat", 200)

def main():
    print("🚀 Starting ZKP IoT Authentication System API Tests")
    print("=" * 60)
    
    tester = ZKPIoTAPITester()
    
    # Test 1: Root endpoint
    tester.test_root_endpoint()
    
    # Test 2: Register multiple devices with different types
    test_devices = [
        {
            "device_name": "Smart Thermostat",
            "device_type": "smart_home",
            "manufacturer": "TechCorp",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "location": "Living Room"
        },
        {
            "device_name": "Heart Monitor",
            "device_type": "healthcare", 
            "manufacturer": "MedTech",
            "mac_address": "AA:BB:CC:DD:EE:02",
            "location": "Patient Room 101"
        },
        {
            "device_name": "Industrial Sensor",
            "device_type": "industrial",
            "manufacturer": "IndustrialCorp",
            "mac_address": "AA:BB:CC:DD:EE:03", 
            "location": "Factory Floor A"
        }
    ]
    
    device_ids = []
    for device in test_devices:
        device_id = tester.test_register_device(device)
        if device_id:
            device_ids.append(device_id)
    
    # Test 3: Get all devices
    tester.test_get_devices()
    
    # Test 4: Authenticate devices with both methods
    for device_id in device_ids:
        # Test ZKP authentication
        tester.test_authenticate_device(device_id, "zero_knowledge")
        time.sleep(0.5)  # Small delay between requests
        
        # Test traditional authentication
        tester.test_authenticate_device(device_id, "traditional")
        time.sleep(0.5)
    
    # Test 5: Get authentication logs
    tester.test_get_auth_logs()
    
    # Test 6: Get security events
    tester.test_get_security_events()
    
    # Test 7: Simulate threat (only if we have devices)
    if device_ids:
        tester.test_simulate_threat()
    
    # Test 8: Get dashboard stats
    tester.test_get_dashboard_stats()
    
    # Print final results
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {tester.tests_passed}/{tester.tests_run} tests passed")
    
    if tester.created_devices:
        print(f"\n📝 Created {len(tester.created_devices)} test devices:")
        for device in tester.created_devices:
            print(f"   • {device['device_name']} (ID: {device['id'][:8]}...)")
    
    success_rate = (tester.tests_passed / tester.tests_run) * 100 if tester.tests_run > 0 else 0
    print(f"\n🎯 Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 90:
        print("🎉 Backend API tests PASSED - Ready for frontend testing!")
        return 0
    elif success_rate >= 70:
        print("⚠️  Backend API tests PARTIALLY PASSED - Some issues found")
        return 1
    else:
        print("❌ Backend API tests FAILED - Major issues found")
        return 2

if __name__ == "__main__":
    sys.exit(main())