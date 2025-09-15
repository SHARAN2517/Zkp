#!/usr/bin/env python3

import requests
import sys
import json
from datetime import datetime
import hashlib

class AshCodexZKPAPITester:
    def __init__(self, base_url="https://zkblock-iot.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.token = None
        self.tests_run = 0
        self.tests_passed = 0
        self.current_user = None

    def log_test(self, name, success, details=""):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED {details}")
        else:
            print(f"❌ {name} - FAILED {details}")
        return success

    def make_request(self, method, endpoint, data=None, expected_status=200, auth_required=True):
        """Make HTTP request with proper headers"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if auth_required and self.token:
            headers['Authorization'] = f'Bearer {self.token}'

        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)

            success = response.status_code == expected_status
            return success, response.json() if response.content else {}, response.status_code

        except requests.exceptions.RequestException as e:
            return False, {"error": str(e)}, 0
        except json.JSONDecodeError:
            return False, {"error": "Invalid JSON response"}, response.status_code

    def generate_zkp_proof(self, username, secret):
        """Generate ZKP proof for testing"""
        combined = f"{secret}:{username}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def test_login(self, username, password, zkp_secret=None):
        """Test user login with optional ZKP"""
        login_data = {
            "username": username,
            "password": password
        }
        
        # Add ZKP proof if secret provided
        if zkp_secret:
            login_data["zkp_proof"] = self.generate_zkp_proof(username, zkp_secret)

        success, response, status_code = self.make_request(
            'POST', 'auth/login', login_data, 200, auth_required=False
        )
        
        if success and 'access_token' in response:
            self.token = response['access_token']
            self.current_user = response.get('user', {})
            return self.log_test(f"Login ({username})", True, f"- Role: {self.current_user.get('role', 'unknown')}")
        else:
            return self.log_test(f"Login ({username})", False, f"- Status: {status_code}, Response: {response}")

    def test_get_current_user(self):
        """Test getting current user info"""
        success, response, status_code = self.make_request('GET', 'auth/me')
        
        if success and 'username' in response:
            return self.log_test("Get Current User", True, f"- User: {response['username']}")
        else:
            return self.log_test("Get Current User", False, f"- Status: {status_code}")

    def test_dashboard_stats(self):
        """Test dashboard statistics endpoint"""
        success, response, status_code = self.make_request('GET', 'dashboard-stats')
        
        expected_fields = ['total_devices', 'online_devices', 'successful_auths_today', 
                          'failed_auths_today', 'avg_privacy_score', 'threat_level',
                          'ml_predictions_today', 'anomalies_detected', 'maintenance_alerts']
        
        if success and all(field in response for field in expected_fields):
            return self.log_test("Dashboard Stats", True, f"- Devices: {response.get('total_devices', 0)}, Threat Level: {response.get('threat_level', 'unknown')}")
        else:
            return self.log_test("Dashboard Stats", False, f"- Status: {status_code}, Missing fields")

    def test_device_registration(self):
        """Test device registration"""
        device_data = {
            "device_name": f"Test Device {datetime.now().strftime('%H%M%S')}",
            "device_type": "smart_home",
            "manufacturer": "TestCorp",
            "mac_address": f"AA:BB:CC:DD:EE:{datetime.now().strftime('%S')}",
            "location": "Test Lab"
        }
        
        success, response, status_code = self.make_request('POST', 'devices', device_data, 201)
        
        if success and 'id' in response:
            self.test_device_id = response['id']
            return self.log_test("Device Registration", True, f"- Device ID: {response['id'][:8]}...")
        else:
            return self.log_test("Device Registration", False, f"- Status: {status_code}, Response: {response}")

    def test_get_devices(self):
        """Test getting all devices"""
        success, response, status_code = self.make_request('GET', 'devices')
        
        if success and isinstance(response, list):
            device_count = len(response)
            return self.log_test("Get Devices", True, f"- Found {device_count} devices")
        else:
            return self.log_test("Get Devices", False, f"- Status: {status_code}")

    def test_device_authentication(self):
        """Test device authentication"""
        if not hasattr(self, 'test_device_id'):
            return self.log_test("Device Authentication", False, "- No device ID available")

        success, response, status_code = self.make_request(
            'POST', f'authenticate/{self.test_device_id}?auth_method=zero_knowledge', 
            None, 200
        )
        
        if success and 'success' in response:
            return self.log_test("Device Authentication", True, f"- Auth Success: {response['success']}, Risk Score: {response.get('risk_score', 'N/A')}")
        else:
            return self.log_test("Device Authentication", False, f"- Status: {status_code}")

    def test_ml_insights(self):
        """Test ML insights endpoint"""
        success, response, status_code = self.make_request('GET', 'ml/insights')
        
        if success and isinstance(response, list):
            insights_count = len(response)
            return self.log_test("ML Insights", True, f"- Found {insights_count} insights")
        else:
            return self.log_test("ML Insights", False, f"- Status: {status_code}")

    def test_threat_predictions(self):
        """Test threat predictions (Admin/Analyst only)"""
        if self.current_user.get('role') not in ['admin', 'security_analyst']:
            return self.log_test("Threat Predictions", True, "- Skipped (insufficient role)")

        success, response, status_code = self.make_request('GET', 'ml/predictions')
        
        if success and isinstance(response, list):
            predictions_count = len(response)
            return self.log_test("Threat Predictions", True, f"- Found {predictions_count} predictions")
        else:
            return self.log_test("Threat Predictions", False, f"- Status: {status_code}")

    def test_authentication_logs(self):
        """Test authentication logs"""
        success, response, status_code = self.make_request('GET', 'authentication-logs')
        
        if success and isinstance(response, list):
            logs_count = len(response)
            return self.log_test("Authentication Logs", True, f"- Found {logs_count} logs")
        else:
            return self.log_test("Authentication Logs", False, f"- Status: {status_code}")

    def test_security_events(self):
        """Test security events"""
        success, response, status_code = self.make_request('GET', 'security-events')
        
        if success and isinstance(response, list):
            events_count = len(response)
            return self.log_test("Security Events", True, f"- Found {events_count} events")
        else:
            return self.log_test("Security Events", False, f"- Status: {status_code}")

    def test_simulate_threat(self):
        """Test threat simulation (Admin/Analyst only)"""
        if self.current_user.get('role') not in ['admin', 'security_analyst']:
            return self.log_test("Simulate Threat", True, "- Skipped (insufficient role)")

        success, response, status_code = self.make_request('GET', 'simulate-threat')
        
        if success and 'message' in response:
            return self.log_test("Simulate Threat", True, f"- {response['message']}")
        else:
            return self.log_test("Simulate Threat", False, f"- Status: {status_code}")

    def run_comprehensive_tests(self):
        """Run all API tests"""
        print("🚀 Starting AshCodex ZKP IoT Authentication System API Tests")
        print("=" * 70)
        
        # Test different user roles
        test_users = [
            ("admin", "admin123", "demo_secret_admin"),
            ("analyst", "analyst123", "demo_secret_analyst"), 
            ("manager", "manager123", "demo_secret_manager")
        ]
        
        for username, password, zkp_secret in test_users:
            print(f"\n🔐 Testing with {username} role:")
            print("-" * 40)
            
            # Login tests
            if not self.test_login(username, password):
                continue
                
            # Test with ZKP
            if not self.test_login(username, password, zkp_secret):
                continue
            
            # Core API tests
            self.test_get_current_user()
            self.test_dashboard_stats()
            
            # Device management tests (Admin/Manager only)
            if self.current_user.get('role') in ['admin', 'device_manager']:
                self.test_device_registration()
                
            self.test_get_devices()
            
            # Authentication test (if device was registered)
            if hasattr(self, 'test_device_id'):
                self.test_device_authentication()
            
            # ML and security tests
            self.test_ml_insights()
            self.test_threat_predictions()
            self.test_authentication_logs()
            self.test_security_events()
            self.test_simulate_threat()
            
            # Clear token for next user
            self.token = None
            self.current_user = None

        # Final results
        print("\n" + "=" * 70)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed! Backend API is fully functional.")
            return 0
        else:
            print(f"⚠️  {self.tests_run - self.tests_passed} tests failed. Check the issues above.")
            return 1

def main():
    tester = AshCodexZKPAPITester()
    return tester.run_comprehensive_tests()

if __name__ == "__main__":
    sys.exit(main())