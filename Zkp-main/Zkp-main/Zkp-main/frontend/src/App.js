import React, { useState, useEffect } from "react";
import "./App.css";
import axios from "axios";
import { Shield, Cpu, Activity, Lock, Users, AlertTriangle, CheckCircle, XCircle, Eye, EyeOff } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Label } from "./components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./components/ui/select";
import { Badge } from "./components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { Alert, AlertDescription } from "./components/ui/alert";
import { Progress } from "./components/ui/progress";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function App() {
  const [devices, setDevices] = useState([]);
  const [authLogs, setAuthLogs] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);
  const [dashboardStats, setDashboardStats] = useState({});
  const [loading, setLoading] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [showPrivacyComparison, setShowPrivacyComparison] = useState(false);

  // Device registration form state
  const [newDevice, setNewDevice] = useState({
    device_name: "",
    device_type: "smart_home",
    manufacturer: "",
    mac_address: "",
    location: ""
  });

  // Fetch data functions
  const fetchDevices = async () => {
    try {
      const response = await axios.get(`${API}/devices`);
      setDevices(response.data);
    } catch (error) {
      console.error("Error fetching devices:", error);
    }
  };

  const fetchAuthLogs = async () => {
    try {
      const response = await axios.get(`${API}/authentication-logs`);
      setAuthLogs(response.data);
    } catch (error) {
      console.error("Error fetching auth logs:", error);
    }
  };

  const fetchSecurityEvents = async () => {
    try {
      const response = await axios.get(`${API}/security-events`);
      setSecurityEvents(response.data);
    } catch (error) {
      console.error("Error fetching security events:", error);
    }
  };

  const fetchDashboardStats = async () => {
    try {
      const response = await axios.get(`${API}/dashboard-stats`);
      setDashboardStats(response.data);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
    }
  };

  const fetchAllData = async () => {
    await Promise.all([
      fetchDevices(),
      fetchAuthLogs(),
      fetchSecurityEvents(),
      fetchDashboardStats()
    ]);
  };

  useEffect(() => {
    fetchAllData();
    // Refresh data every 30 seconds
    const interval = setInterval(fetchAllData, 30000);
    return () => clearInterval(interval);
  }, []);

  // Device registration
  const registerDevice = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await axios.post(`${API}/devices`, newDevice);
      setNewDevice({
        device_name: "",
        device_type: "smart_home",
        manufacturer: "",
        mac_address: "",
        location: ""
      });
      fetchAllData();
    } catch (error) {
      console.error("Error registering device:", error);
    }
    setLoading(false);
  };

  // Device authentication
  const authenticateDevice = async (deviceId, method = "zero_knowledge") => {
    setLoading(true);
    try {
      await axios.post(`${API}/authenticate/${deviceId}`, null, {
        params: { auth_method: method }
      });
      fetchAllData();
    } catch (error) {
      console.error("Error authenticating device:", error);
    }
    setLoading(false);
  };

  // Simulate threat
  const simulateThreat = async () => {
    try {
      await axios.get(`${API}/simulate-threat`);
      fetchAllData();
    } catch (error) {
      console.error("Error simulating threat:", error);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "online": return "text-green-600";
      case "offline": return "text-red-600";
      case "authenticating": return "text-yellow-600";
      case "compromised": return "text-red-800";
      default: return "text-gray-600";
    }
  };

  const getThreatLevelColor = (level) => {
    switch (level) {
      case "low": return "text-green-600 bg-green-50";
      case "medium": return "text-yellow-600 bg-yellow-50";
      case "high": return "text-red-600 bg-red-50";
      case "critical": return "text-red-800 bg-red-100";
      default: return "text-gray-600 bg-gray-50";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-md border-b border-slate-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-xl">
                <Shield className="h-8 w-8 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-slate-900">ZKP IoT Authentication</h1>
                <p className="text-slate-600 text-sm">Zero-Knowledge Proof Security System</p>
              </div>
            </div>
            <Button onClick={simulateThreat} variant="outline" className="hover:bg-red-50">
              <AlertTriangle className="h-4 w-4 mr-2" />
              Simulate Threat
            </Button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Dashboard Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card className="bg-white/60 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-slate-600">Total Devices</CardTitle>
              <Cpu className="h-4 w-4 text-slate-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-slate-900">{dashboardStats.total_devices || 0}</div>
              <p className="text-xs text-slate-500">
                {dashboardStats.online_devices || 0} online
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white/60 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-slate-600">Auth Success</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{dashboardStats.successful_auths_today || 0}</div>
              <p className="text-xs text-slate-500">Today</p>
            </CardContent>
          </Card>

          <Card className="bg-white/60 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-slate-600">Privacy Score</CardTitle>
              <Eye className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{dashboardStats.avg_privacy_score || 0}%</div>
              <Progress value={dashboardStats.avg_privacy_score || 0} className="mt-2 h-2" />
            </CardContent>
          </Card>

          <Card className="bg-white/60 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-slate-600">Threat Level</CardTitle>
              <AlertTriangle className="h-4 w-4 text-orange-500" />
            </CardHeader>
            <CardContent>
              <Badge className={getThreatLevelColor(dashboardStats.threat_level)}>
                {dashboardStats.threat_level || "low"}
              </Badge>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="devices" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4 bg-white/60 backdrop-blur-sm">
            <TabsTrigger value="devices">Device Management</TabsTrigger>
            <TabsTrigger value="zkp">ZKP Authentication</TabsTrigger>
            <TabsTrigger value="logs">Security Logs</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
          </TabsList>

          {/* Device Management Tab */}
          <TabsContent value="devices" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Device Registration Form */}
              <Card className="lg:col-span-1 bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Users className="h-5 w-5 mr-2" />
                    Register New Device
                  </CardTitle>
                  <CardDescription>
                    Add a new IoT device with ZKP authentication
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form onSubmit={registerDevice} className="space-y-4">
                    <div>
                      <Label htmlFor="device_name">Device Name</Label>
                      <Input
                        id="device_name"
                        value={newDevice.device_name}
                        onChange={(e) => setNewDevice({...newDevice, device_name: e.target.value})}
                        placeholder="Smart Thermostat"
                        required
                      />
                    </div>
                    
                    <div>
                      <Label htmlFor="device_type">Device Type</Label>
                      <Select 
                        value={newDevice.device_type} 
                        onValueChange={(value) => setNewDevice({...newDevice, device_type: value})}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="smart_home">Smart Home</SelectItem>
                          <SelectItem value="healthcare">Healthcare</SelectItem>
                          <SelectItem value="industrial">Industrial</SelectItem>
                          <SelectItem value="wearable">Wearable</SelectItem>
                          <SelectItem value="sensor">Sensor</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label htmlFor="manufacturer">Manufacturer</Label>
                      <Input
                        id="manufacturer"
                        value={newDevice.manufacturer}
                        onChange={(e) => setNewDevice({...newDevice, manufacturer: e.target.value})}
                        placeholder="TechCorp"
                        required
                      />
                    </div>

                    <div>
                      <Label htmlFor="mac_address">MAC Address</Label>
                      <Input
                        id="mac_address"
                        value={newDevice.mac_address}
                        onChange={(e) => setNewDevice({...newDevice, mac_address: e.target.value})}
                        placeholder="AA:BB:CC:DD:EE:FF"
                        required
                      />
                    </div>

                    <div>
                      <Label htmlFor="location">Location</Label>
                      <Input
                        id="location"
                        value={newDevice.location}
                        onChange={(e) => setNewDevice({...newDevice, location: e.target.value})}
                        placeholder="Living Room"
                        required
                      />
                    </div>

                    <Button type="submit" disabled={loading} className="w-full">
                      {loading ? "Registering..." : "Register Device"}
                    </Button>
                  </form>
                </CardContent>
              </Card>

              {/* Device List */}
              <Card className="lg:col-span-2 bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Registered Devices</CardTitle>
                  <CardDescription>
                    {devices.length} devices registered with ZKP authentication
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {devices.map((device) => (
                      <div key={device.id} className="flex items-center justify-between p-4 border border-slate-200 rounded-lg bg-white/50">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <h3 className="font-semibold text-slate-900">{device.device_name}</h3>
                            <Badge variant="outline" className={getStatusColor(device.status)}>
                              {device.status}
                            </Badge>
                          </div>
                          <p className="text-sm text-slate-600">{device.manufacturer} • {device.location}</p>
                          <p className="text-xs text-slate-500">MAC: {device.mac_address}</p>
                        </div>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            onClick={() => authenticateDevice(device.id, "zero_knowledge")}
                            disabled={loading}
                            className="bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600"
                          >
                            <Lock className="h-4 w-4 mr-1" />
                            ZKP Auth
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => authenticateDevice(device.id, "traditional")}
                            disabled={loading}
                          >
                            Traditional
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* ZKP Authentication Tab */}
          <TabsContent value="zkp" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Privacy Comparison */}
              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    Authentication Comparison
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setShowPrivacyComparison(!showPrivacyComparison)}
                    >
                      {showPrivacyComparison ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 border border-red-200 rounded-lg bg-red-50">
                      <h4 className="font-semibold text-red-800 mb-2">Traditional Auth</h4>
                      <ul className="text-sm text-red-700 space-y-1">
                        <li>• Credentials exposed</li>
                        <li>• Identity revealed</li>
                        <li>• Vulnerable to interception</li>
                        <li>• Central point of failure</li>
                      </ul>
                      {showPrivacyComparison && (
                        <div className="mt-3 p-2 bg-red-100 rounded text-xs">
                          <strong>Exposed:</strong> Username, Password, Device ID, Location
                        </div>
                      )}
                    </div>
                    
                    <div className="p-4 border border-green-200 rounded-lg bg-green-50">
                      <h4 className="font-semibold text-green-800 mb-2">ZKP Authentication</h4>
                      <ul className="text-sm text-green-700 space-y-1">
                        <li>• Zero credential exposure</li>
                        <li>• Privacy preserved</li>
                        <li>• Cryptographically secure</li>
                        <li>• Decentralized verification</li>
                      </ul>
                      {showPrivacyComparison && (
                        <div className="mt-3 p-2 bg-green-100 rounded text-xs">
                          <strong>Exposed:</strong> Nothing - Only proof of knowledge
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Recent ZKP Authentications */}
              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Recent ZKP Authentications</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {authLogs.filter(log => log.auth_method === "zero_knowledge").slice(0, 5).map((log) => (
                      <div key={log.id} className="flex items-center justify-between p-3 border border-slate-200 rounded-lg bg-white/50">
                        <div>
                          <p className="font-medium text-slate-900">{log.device_name}</p>
                          <p className="text-xs text-slate-500">
                            {new Date(log.timestamp).toLocaleString()}
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          {log.success ? (
                            <CheckCircle className="h-5 w-5 text-green-500" />
                          ) : (
                            <XCircle className="h-5 w-5 text-red-500" />
                          )}
                          <Badge className="bg-green-100 text-green-800">
                            Privacy Protected
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Security Logs Tab */}
          <TabsContent value="logs" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Authentication Logs */}
              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Authentication Logs</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {authLogs.map((log) => (
                      <div key={log.id} className="flex items-center justify-between p-3 border border-slate-200 rounded-lg bg-white/50">
                        <div>
                          <p className="font-medium text-slate-900">{log.device_name}</p>
                          <p className="text-xs text-slate-500">
                            {new Date(log.timestamp).toLocaleString()} • {log.auth_method}
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          {log.success ? (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          ) : (
                            <XCircle className="h-4 w-4 text-red-500" />
                          )}
                          {log.privacy_preserved && (
                            <Badge className="bg-blue-100 text-blue-800 text-xs">
                              Private
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Security Events */}
              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Security Events</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {securityEvents.map((event) => (
                      <div key={event.id} className="p-3 border border-slate-200 rounded-lg bg-white/50">
                        <div className="flex items-center justify-between mb-2">
                          <Badge className={getThreatLevelColor(event.severity)}>
                            {event.severity}
                          </Badge>
                          <span className="text-xs text-slate-500">
                            {new Date(event.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-sm text-slate-700">{event.description}</p>
                        <p className="text-xs text-slate-500 mt-1">Event: {event.event_type}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Analytics Tab */}
          <TabsContent value="analytics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Authentication Methods</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-slate-600">Zero-Knowledge Proof</span>
                      <span className="font-semibold text-green-600">
                        {authLogs.filter(log => log.auth_method === "zero_knowledge").length}
                      </span>  
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-slate-600">Traditional</span>
                      <span className="font-semibold text-blue-600">
                        {authLogs.filter(log => log.auth_method === "traditional").length}
                      </span>
                    </div>
                    <Progress 
                      value={
                        authLogs.length > 0 
                          ? (authLogs.filter(log => log.auth_method === "zero_knowledge").length / authLogs.length) * 100
                          : 0
                      } 
                      className="h-2"
                    />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Device Types</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {["smart_home", "healthcare", "industrial", "wearable", "sensor"].map(type => (
                      <div key={type} className="flex justify-between items-center">
                        <span className="text-sm text-slate-600 capitalize">{type.replace('_', ' ')}</span>
                        <span className="font-semibold">
                          {devices.filter(device => device.device_type === type).length}
                        </span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>System Health</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-slate-600">Uptime</span>
                      <Badge className="bg-green-100 text-green-800">99.9%</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-slate-600">ZKP Success Rate</span>
                      <Badge className="bg-blue-100 text-blue-800">
                        {authLogs.filter(log => log.auth_method === "zero_knowledge" && log.success).length > 0 
                          ? Math.round((authLogs.filter(log => log.auth_method === "zero_knowledge" && log.success).length / authLogs.filter(log => log.auth_method === "zero_knowledge").length) * 100)
                          : 100}%
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-slate-600">Privacy Protected</span>
                      <Badge className="bg-purple-100 text-purple-800">
                        {authLogs.filter(log => log.privacy_preserved).length}
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

export default App;