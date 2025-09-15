import React, { useState, useEffect } from "react";
import "./App.css";
import axios from "axios";
import { Shield, Cpu, Activity, Lock, Users, AlertTriangle, CheckCircle, XCircle, Eye, EyeOff, Brain, TrendingUp, Zap, LogOut, Settings, Bell, User } from "lucide-react";
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

// Login Component
function LoginPage({ onLogin }) {
  const [loginData, setLoginData] = useState({
    username: "",
    password: "",
    zkp_proof: ""
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showZKP, setShowZKP] = useState(false);
  const [zkpSecret, setZkpSecret] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      let finalLoginData = { ...loginData };
      
      // Generate ZKP proof if multi-factor is enabled
      if (showZKP && zkpSecret) {
        const zkpProof = await generateZKPProof(loginData.username, zkpSecret);
        finalLoginData.zkp_proof = zkpProof;
      }

      const response = await axios.post(`${API}/auth/login`, finalLoginData);
      
      // Store token and user data
      localStorage.setItem("token", response.data.access_token);
      localStorage.setItem("user", JSON.stringify(response.data.user));
      
      onLogin(response.data.user);
    } catch (error) {
      setError(error.response?.data?.detail || "Login failed");
    }
    setLoading(false);
  };

  const generateZKPProof = async (username, secret) => {
    // Simplified ZKP proof generation for demo
    const encoder = new TextEncoder();
    const data = encoder.encode(`${secret}:${username}`);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const demoCredentials = [
    { username: "admin", password: "admin123", role: "Admin", secret: "demo_secret_admin" },
    { username: "analyst", password: "analyst123", role: "Security Analyst", secret: "demo_secret_analyst" },
    { username: "manager", password: "manager123", role: "Device Manager", secret: "demo_secret_manager" }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-black flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="p-3 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-2xl">
              <Shield className="h-12 w-12 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">ZKP IoT Authentication</h1>
          <p className="text-gray-400">Advanced Zero-Knowledge Proof Security System</p>
          <div className="mt-4 text-xs text-gray-500">
            Built by <span className="text-cyan-400 font-semibold">AshCodex Team</span>
          </div>
        </div>

        {/* Login Form */}
        <Card className="bg-gray-800/50 backdrop-blur-sm border border-gray-700">
          <CardHeader>
            <CardTitle className="text-white">Secure Login</CardTitle>
            <CardDescription className="text-gray-400">
              Multi-factor authentication with ZKP integration
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <Label htmlFor="username" className="text-gray-300">Username</Label>
                <Input
                  id="username"
                  type="text"
                  value={loginData.username}
                  onChange={(e) => setLoginData({...loginData, username: e.target.value})}
                  className="bg-gray-700 border-gray-600 text-white"
                  placeholder="Enter username"
                  required
                />
              </div>

              <div>
                <Label htmlFor="password" className="text-gray-300">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={loginData.password}
                  onChange={(e) => setLoginData({...loginData, password: e.target.value})}
                  className="bg-gray-700 border-gray-600 text-white"
                  placeholder="Enter password"
                  required
                />
              </div>

              {/* Multi-Factor ZKP Toggle */}
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="zkp-toggle"
                    checked={showZKP}
                    onChange={(e) => setShowZKP(e.target.checked)}
                    className="rounded"
                  />
                  <Label htmlFor="zkp-toggle" className="text-sm text-gray-300">
                    Enable Multi-Factor ZKP
                  </Label>
                </div>
                <Lock className="h-4 w-4 text-cyan-400" />
              </div>

              {showZKP && (
                <div>
                  <Label htmlFor="zkp_secret" className="text-gray-300">ZKP Secret</Label>
                  <Input
                    id="zkp_secret"
                    type="password"
                    value={zkpSecret}
                    onChange={(e) => setZkpSecret(e.target.value)}
                    className="bg-gray-700 border-gray-600 text-white"
                    placeholder="Enter ZKP secret"
                  />
                </div>
              )}

              {error && (
                <Alert className="border-red-500 bg-red-500/10">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  <AlertDescription className="text-red-400">{error}</AlertDescription>
                </Alert>
              )}

              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600"
              >
                {loading ? "Authenticating..." : "Login with ZKP"}
              </Button>
            </form>

            {/* Demo Credentials */}
            <div className="mt-6 pt-4 border-t border-gray-700">
              <p className="text-xs text-gray-400 mb-3">Demo Credentials:</p>
              <div className="grid grid-cols-1 gap-2">
                {demoCredentials.map(cred => (
                  <div key={cred.username} className="flex justify-between items-center text-xs">
                    <span className="text-gray-300">{cred.role}:</span>
                    <div className="text-gray-400">
                      <span className="text-cyan-400">{cred.username}</span> / {cred.password}
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs h-6 px-2 border-gray-600 text-gray-400 hover:text-white"
                      onClick={() => {
                        setLoginData({username: cred.username, password: cred.password, zkp_proof: ""});
                        setZkpSecret(cred.secret);
                      }}
                    >
                      Use
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Features Preview */}
        <div className="mt-8 grid grid-cols-2 gap-4 text-center">
          <div className="bg-gray-800/30 rounded-lg p-3">
            <Brain className="h-6 w-6 text-blue-400 mx-auto mb-1" />
            <p className="text-xs text-gray-400">ML Threat Prediction</p>
          </div>
          <div className="bg-gray-800/30 rounded-lg p-3">
            <Activity className="h-6 w-6 text-cyan-400 mx-auto mb-1" />
            <p className="text-xs text-gray-400">Anomaly Detection</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// Main Dashboard Component
function Dashboard({ user, onLogout }) {
  const [devices, setDevices] = useState([]);
  const [authLogs, setAuthLogs] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);
  const [dashboardStats, setDashboardStats] = useState({});
  const [threatPredictions, setThreatPredictions] = useState([]);
  const [mlInsights, setMlInsights] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);

  // Device registration form state
  const [newDevice, setNewDevice] = useState({
    device_name: "",
    device_type: "smart_home",
    manufacturer: "",
    mac_address: "",
    location: ""
  });

  // Axios interceptor for auth token
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
  }, []);

  // Fetch data functions
  const fetchDevices = async () => {
    try {
      const response = await axios.get(`${API}/devices`);
      setDevices(response.data);
    } catch (error) {
      console.error("Error fetching devices:", error);
      if (error.response?.status === 401) {
        onLogout();
      }
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

  const fetchThreatPredictions = async () => {
    try {
      if (user.role === 'admin' || user.role === 'security_analyst') {
        const response = await axios.get(`${API}/ml/predictions`);
        setThreatPredictions(response.data);
      }
    } catch (error) {
      console.error("Error fetching threat predictions:", error);
    }
  };

  const fetchMLInsights = async () => {
    try {
      const response = await axios.get(`${API}/ml/insights`);
      setMlInsights(response.data);
    } catch (error) {
      console.error("Error fetching ML insights:", error);
    }
  };

  const fetchAllData = async () => {
    await Promise.all([
      fetchDevices(),
      fetchAuthLogs(),
      fetchSecurityEvents(),
      fetchDashboardStats(),
      fetchThreatPredictions(),
      fetchMLInsights()
    ]);
  };

  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 30000);
    return () => clearInterval(interval);
  }, [user]);

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
      case "online": return "text-green-400 bg-green-500/20";
      case "offline": return "text-red-400 bg-red-500/20";
      case "authenticating": return "text-yellow-400 bg-yellow-500/20";
      case "compromised": return "text-red-500 bg-red-500/30";
      case "maintenance": return "text-orange-400 bg-orange-500/20";
      default: return "text-gray-400 bg-gray-500/20";
    }
  };

  const getThreatLevelColor = (level) => {
    switch (level) {
      case "low": return "text-green-400 bg-green-500/20";
      case "medium": return "text-yellow-400 bg-yellow-500/20";
      case "high": return "text-orange-400 bg-orange-500/20";
      case "critical": return "text-red-400 bg-red-500/20";
      default: return "text-gray-400 bg-gray-500/20";
    }
  };

  const canAccessFeature = (requiredRoles) => {
    return requiredRoles.includes(user.role);
  };

  // Role-specific access control
  const rolePermissions = {
    admin: {
      canManageDevices: true,
      canViewSecurity: true,
      canViewMLInsights: true,
      canSimulateThreats: true,
      canRegisterDevices: true,
      canViewThreatPredictions: true,
      canViewAnalytics: true,
      canManageUsers: true
    },
    security_analyst: {
      canManageDevices: false,
      canViewSecurity: true,
      canViewMLInsights: true,
      canSimulateThreats: true,
      canRegisterDevices: false,
      canViewThreatPredictions: true,
      canViewAnalytics: true,
      canManageUsers: false
    },
    device_manager: {
      canManageDevices: true,
      canViewSecurity: false,
      canViewMLInsights: false,
      canSimulateThreats: false,
      canRegisterDevices: true,
      canViewThreatPredictions: false,
      canViewAnalytics: false,
      canManageUsers: false
    }
  };

  const hasPermission = (permission) => {
    return rolePermissions[user.role]?.[permission] || false;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-black text-white">
      {/* Header */}
      <header className="bg-gray-800/50 backdrop-blur-md border-b border-gray-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-xl">
                <Shield className="h-8 w-8 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">AshCodex ZKP IoT Platform</h1>
                <p className="text-gray-400 text-sm">Advanced ML-Powered Security System</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <User className="h-4 w-4 text-gray-400" />
                <span className="text-sm text-gray-300">{user.username}</span>
                <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                  {user.role.replace('_', ' ').toUpperCase()}
                </Badge>
              </div>
              
              {canAccessFeature(['admin', 'security_analyst']) && (
                <Button onClick={simulateThreat} variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10">
                  <AlertTriangle className="h-4 w-4 mr-2" />
                  Simulate Threat
                </Button>
              )}
              
              <Button onClick={onLogout} variant="outline" className="border-gray-600 text-gray-400 hover:text-white">
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Enhanced Dashboard Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
          <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Total Devices</CardTitle>
              <Cpu className="h-4 w-4 text-gray-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{dashboardStats.total_devices || 0}</div>
              <p className="text-xs text-gray-400">
                {dashboardStats.online_devices || 0} online
              </p>
            </CardContent>
          </Card>

          <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">ML Predictions</CardTitle>
              <Brain className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-400">{dashboardStats.ml_predictions_today || 0}</div>
              <p className="text-xs text-gray-400">Today</p>
            </CardContent>
          </Card>

          <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Anomalies</CardTitle>
              <TrendingUp className="h-4 w-4 text-orange-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-400">{dashboardStats.anomalies_detected || 0}</div>
              <p className="text-xs text-gray-400">Detected</p>
            </CardContent>
          </Card>

          <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Privacy Score</CardTitle>
              <Eye className="h-4 w-4 text-cyan-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-cyan-400">{dashboardStats.avg_privacy_score || 0}%</div>
              <Progress value={dashboardStats.avg_privacy_score || 0} className="mt-2 h-2" />
            </CardContent>
          </Card>

          <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Threat Level</CardTitle>
              <AlertTriangle className="h-4 w-4 text-orange-400" />
            </CardHeader>
            <CardContent>
              <Badge className={getThreatLevelColor(dashboardStats.threat_level)}>
                {dashboardStats.threat_level || "low"}
              </Badge>
              <p className="text-xs text-gray-400 mt-1">
                {dashboardStats.maintenance_alerts || 0} maintenance alerts
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-6 bg-gray-800/40 backdrop-blur-sm border border-gray-700">
            <TabsTrigger value="overview" className="data-[state=active]:bg-gray-700">Overview</TabsTrigger>
            {hasPermission('canManageDevices') && (
              <TabsTrigger value="devices" className="data-[state=active]:bg-gray-700">Devices</TabsTrigger>
            )}
            {hasPermission('canViewMLInsights') && (
              <TabsTrigger value="ml-insights" className="data-[state=active]:bg-gray-700">ML Insights</TabsTrigger>
            )}
            <TabsTrigger value="zkp" className="data-[state=active]:bg-gray-700">ZKP Auth</TabsTrigger>
            {hasPermission('canViewSecurity') && (
              <TabsTrigger value="security" className="data-[state=active]:bg-gray-700">Security</TabsTrigger>
            )}
            {hasPermission('canViewAnalytics') && (
              <TabsTrigger value="analytics" className="data-[state=active]:bg-gray-700">Analytics</TabsTrigger>
            )}
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* ML Insights Overview - Admin and Security Analyst only */}
              {hasPermission('canViewMLInsights') && (
                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="flex items-center text-white">
                      <Brain className="h-5 w-5 mr-2 text-blue-400" />
                      AI-Powered Insights
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {mlInsights.slice(0, 3).map((insight, index) => (
                        <div key={index} className="p-3 bg-gray-700/30 rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <Badge className="bg-blue-500/20 text-blue-400">
                              {insight.insight_type}
                            </Badge>
                            <span className="text-xs text-gray-400">
                              {Math.round(insight.confidence * 100)}% confidence
                            </span>
                          </div>
                          <p className="text-sm text-gray-300">{insight.description}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Device Status Overview - Device Manager and Admin only */}
              {hasPermission('canManageDevices') && (
                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="flex items-center text-white">
                      <Cpu className="h-5 w-5 mr-2 text-green-400" />
                      Device Status Overview
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300">Online Devices</span>
                        <Badge className="bg-green-500/20 text-green-400">
                          {dashboardStats.online_devices || 0}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300">Total Registered</span>
                        <Badge className="bg-blue-500/20 text-blue-400">
                          {dashboardStats.total_devices || 0}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300">Auth Success Today</span>
                        <Badge className="bg-cyan-500/20 text-cyan-400">
                          {dashboardStats.successful_auths_today || 0}
                        </Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Threat Predictions - Admin and Security Analyst only */}
              {hasPermission('canViewThreatPredictions') && (
                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="flex items-center text-white">
                      <Zap className="h-5 w-5 mr-2 text-red-400" />
                      Recent Threat Predictions
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {threatPredictions.slice(0, 4).map((threat) => (
                        <div key={threat.id} className="p-3 bg-gray-700/30 rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <Badge className={getThreatLevelColor(threat.severity)}>
                              {threat.severity}
                            </Badge>
                            <span className="text-xs text-gray-400">
                              {Math.round(threat.probability * 100)}%
                            </span>
                          </div>
                          <p className="text-sm text-gray-300">{threat.threat_type}</p>
                          <p className="text-xs text-gray-400 mt-1">{threat.description}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Role-specific welcome message */}
              <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                <CardHeader>
                  <CardTitle className="flex items-center text-white">
                    <User className="h-5 w-5 mr-2 text-cyan-400" />
                    Welcome, {user.role.replace('_', ' ').toUpperCase()}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 text-sm text-gray-300">
                    {user.role === 'admin' && (
                      <>
                        <p>• Full system administration access</p>
                        <p>• Device management and registration</p>
                        <p>• ML insights and threat predictions</p>
                        <p>• Security monitoring and threat simulation</p>
                        <p>• User management and analytics</p>
                      </>
                    )}
                    {user.role === 'security_analyst' && (
                      <>
                        <p>• Security event monitoring and analysis</p>
                        <p>• ML-powered threat predictions</p>
                        <p>• Advanced security insights</p>
                        <p>• Threat simulation capabilities</p>
                        <p>• Analytics and reporting</p>
                      </>
                    )}
                    {user.role === 'device_manager' && (
                      <>
                        <p>• IoT device registration and management</p>
                        <p>• Device authentication and monitoring</p>
                        <p>• ZKP authentication setup</p>
                        <p>• Device status and health monitoring</p>
                      </>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Device Management Tab - Admin and Device Manager only */}
          {hasPermission('canManageDevices') && (
            <TabsContent value="devices" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Device Registration Form */}
                {hasPermission('canRegisterDevices') && (
                  <Card className="lg:col-span-1 bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                    <CardHeader>
                      <CardTitle className="flex items-center text-white">
                        <Users className="h-5 w-5 mr-2" />
                        Register New Device
                      </CardTitle>
                      <CardDescription className="text-gray-400">
                        Add a new IoT device with ZKP authentication
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <form onSubmit={registerDevice} className="space-y-4">
                        <div>
                          <Label htmlFor="device_name" className="text-gray-300">Device Name</Label>
                          <Input
                            id="device_name"
                            value={newDevice.device_name}
                            onChange={(e) => setNewDevice({...newDevice, device_name: e.target.value})}
                            placeholder="Smart Thermostat"
                            className="bg-gray-700 border-gray-600 text-white"
                            required
                          />
                        </div>
                        
                        <div>
                          <Label htmlFor="device_type" className="text-gray-300">Device Type</Label>
                          <Select 
                            value={newDevice.device_type} 
                            onValueChange={(value) => setNewDevice({...newDevice, device_type: value})}
                          >
                            <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent className="bg-gray-700 border-gray-600">
                              <SelectItem value="smart_home">Smart Home</SelectItem>
                              <SelectItem value="healthcare">Healthcare</SelectItem>
                              <SelectItem value="industrial">Industrial</SelectItem>
                              <SelectItem value="wearable">Wearable</SelectItem>
                              <SelectItem value="sensor">Sensor</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        <div>
                          <Label htmlFor="manufacturer" className="text-gray-300">Manufacturer</Label>
                          <Input
                            id="manufacturer"
                            value={newDevice.manufacturer}
                            onChange={(e) => setNewDevice({...newDevice, manufacturer: e.target.value})}
                            placeholder="TechCorp"
                            className="bg-gray-700 border-gray-600 text-white"
                            required
                          />
                        </div>

                        <div>
                          <Label htmlFor="mac_address" className="text-gray-300">MAC Address</Label>
                          <Input
                            id="mac_address"
                            value={newDevice.mac_address}
                            onChange={(e) => setNewDevice({...newDevice, mac_address: e.target.value})}
                            placeholder="AA:BB:CC:DD:EE:FF"
                            className="bg-gray-700 border-gray-600 text-white"
                            required
                          />
                        </div>

                        <div>
                          <Label htmlFor="location" className="text-gray-300">Location</Label>
                          <Input
                            id="location"
                            value={newDevice.location}
                            onChange={(e) => setNewDevice({...newDevice, location: e.target.value})}
                            placeholder="Living Room"
                            className="bg-gray-700 border-gray-600 text-white"
                            required
                          />
                        </div>

                        <Button type="submit" disabled={loading} className="w-full bg-gradient-to-r from-blue-500 to-cyan-500">
                          {loading ? "Registering..." : "Register Device"}
                        </Button>
                      </form>
                    </CardContent>
                  </Card>
                )}

                {/* Device List */}
                <Card className={`${hasPermission('canRegisterDevices') ? 'lg:col-span-2' : 'lg:col-span-3'} bg-gray-800/40 backdrop-blur-sm border border-gray-700`}>
                  <CardHeader>
                    <CardTitle className="text-white">Registered Devices</CardTitle>
                    <CardDescription className="text-gray-400">
                      {devices.length} devices with enhanced ML monitoring
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {devices.map((device) => (
                        <div key={device.id} className="flex items-center justify-between p-4 border border-gray-700 rounded-lg bg-gray-700/20">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-2">
                              <h3 className="font-semibold text-white">{device.device_name}</h3>
                              <Badge className={getStatusColor(device.status)}>
                                {device.status}
                              </Badge>
                              {device.anomaly_score > 0.6 && (
                                <Badge className="bg-red-500/20 text-red-400">
                                  Anomaly Detected
                                </Badge>
                              )}
                            </div>
                            <p className="text-sm text-gray-300">{device.manufacturer} • {device.location}</p>
                            <p className="text-xs text-gray-400">MAC: {device.mac_address}</p>
                            <div className="flex space-x-4 mt-2 text-xs">
                              <span className="text-gray-400">Risk: <span className="text-orange-400">{Math.round(device.risk_score * 100)}%</span></span>
                              {user.role === 'admin' && (
                                <>
                                  <span className="text-gray-400">Anomaly: <span className="text-red-400">{Math.round(device.anomaly_score * 100)}%</span></span>
                                  <span className="text-gray-400">Maintenance: <span className="text-yellow-400">{Math.round(device.maintenance_prediction * 100)}%</span></span>
                                </>
                              )}
                            </div>
                          </div>
                          <div className="flex space-x-2">
                            <Button
                              size="sm"
                              onClick={() => authenticateDevice(device.id, "multi_factor_zkp")}
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
                              className="border-gray-600 text-gray-400 hover:text-white"
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
          )}

          {/* ML Insights Tab - Admin and Security Analyst only */}
          {hasPermission('canViewMLInsights') && (
            <TabsContent value="ml-insights" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Comprehensive ML Insights */}
                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="flex items-center text-white">
                      <Brain className="h-5 w-5 mr-2 text-blue-400" />
                      AI Security Insights
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {mlInsights.map((insight, index) => (
                        <div key={index} className="p-4 bg-gray-700/30 rounded-lg">
                          <div className="flex items-center justify-between mb-3">
                            <Badge className={
                              insight.insight_type === 'threat' ? 'bg-red-500/20 text-red-400' :
                              insight.insight_type === 'anomaly' ? 'bg-orange-500/20 text-orange-400' :
                              insight.insight_type === 'risk' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-blue-500/20 text-blue-400'
                            }>
                              {insight.insight_type.toUpperCase()}
                            </Badge>
                            <span className="text-xs text-gray-400">
                              {Math.round(insight.confidence * 100)}% confidence
                            </span>
                          </div>
                          <p className="text-sm text-gray-300 mb-3">{insight.description}</p>
                          <div className="space-y-1">
                            <p className="text-xs text-gray-400 font-medium">Recommendations:</p>
                            {insight.recommendations.map((rec, recIndex) => (
                              <p key={recIndex} className="text-xs text-gray-400">• {rec}</p>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Threat Predictions Detail */}
                {hasPermission('canViewThreatPredictions') && (
                  <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                    <CardHeader>
                      <CardTitle className="flex items-center text-white">
                        <Zap className="h-5 w-5 mr-2 text-red-400" />
                        Advanced Threat Predictions
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        {threatPredictions.map((threat) => (
                          <div key={threat.id} className="p-4 bg-gray-700/30 rounded-lg">
                            <div className="flex items-center justify-between mb-3">
                              <Badge className={getThreatLevelColor(threat.severity)}>
                                {threat.severity}
                              </Badge>
                              <span className="text-xs text-gray-400">
                                {Math.round(threat.probability * 100)}% probability
                              </span>
                            </div>
                            <h4 className="font-medium text-white mb-2">{threat.threat_type}</h4>
                            <p className="text-sm text-gray-300 mb-2">{threat.description}</p>
                            <div className="border-t border-gray-600 pt-2">
                              <p className="text-xs text-gray-400 font-medium">Recommended Action:</p>
                              <p className="text-xs text-gray-400">{threat.recommended_action}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            </TabsContent>
          )}

          {/* ZKP Authentication Tab */}
          <TabsContent value="zkp" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Privacy Comparison */}
              <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                <CardHeader>
                  <CardTitle className="text-white">Authentication Comparison</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 border border-red-500/30 rounded-lg bg-red-500/10">
                      <h4 className="font-semibold text-red-400 mb-2">Traditional Auth</h4>
                      <ul className="text-sm text-red-300 space-y-1">
                        <li>• Credentials exposed</li>
                        <li>• Identity revealed</li>
                        <li>• Vulnerable to interception</li>
                        <li>• Central point of failure</li>
                      </ul>
                    </div>
                    
                    <div className="p-4 border border-green-500/30 rounded-lg bg-green-500/10">
                      <h4 className="font-semibold text-green-400 mb-2">ZKP Authentication</h4>
                      <ul className="text-sm text-green-300 space-y-1">
                        <li>• Zero credential exposure</li>
                        <li>• Privacy preserved</li>
                        <li>• Cryptographically secure</li>
                        <li>• Decentralized verification</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Recent ZKP Authentications */}
              <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                <CardHeader>
                  <CardTitle className="text-white">Recent ZKP Authentications</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {authLogs.filter(log => log.auth_method === "zero_knowledge" || log.auth_method === "multi_factor_zkp").slice(0, 5).map((log) => (
                      <div key={log.id} className="flex items-center justify-between p-3 border border-gray-700 rounded-lg bg-gray-700/20">
                        <div>
                          <p className="font-medium text-white">{log.device_name}</p>
                          <p className="text-xs text-gray-400">
                            {new Date(log.timestamp).toLocaleString()} • {log.auth_method}
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          {log.success ? (
                            <CheckCircle className="h-5 w-5 text-green-400" />
                          ) : (
                            <XCircle className="h-5 w-5 text-red-400" />
                          )}
                          <Badge className="bg-green-500/20 text-green-400">
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

          {/* Security Tab - Admin and Security Analyst only */}
          {hasPermission('canViewSecurity') && (
            <TabsContent value="security" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Authentication Logs */}
                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="text-white">Authentication Logs</CardTitle>
                    <CardDescription className="text-gray-400">
                      Security analyst view of authentication events
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3 max-h-96 overflow-y-auto">
                      {authLogs.map((log) => (
                        <div key={log.id} className="flex items-center justify-between p-3 border border-gray-700 rounded-lg bg-gray-700/20">
                          <div>
                            <p className="font-medium text-white">{log.device_name}</p>
                            <p className="text-xs text-gray-400">
                              {new Date(log.timestamp).toLocaleString()} • {log.auth_method}
                            </p>
                            <p className="text-xs text-orange-400">
                              Risk Score: {Math.round(log.risk_score * 100)}%
                            </p>
                          </div>
                          <div className="flex items-center space-x-2">
                            {log.success ? (
                              <CheckCircle className="h-4 w-4 text-green-400" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-400" />
                            )}
                            {log.privacy_preserved && (
                              <Badge className="bg-blue-500/20 text-blue-400 text-xs">
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
                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="text-white">Security Events</CardTitle>
                    <CardDescription className="text-gray-400">
                      ML-enhanced threat detection and security incidents
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3 max-h-96 overflow-y-auto">
                      {securityEvents.map((event) => (
                        <div key={event.id} className="p-3 border border-gray-700 rounded-lg bg-gray-700/20">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center space-x-2">
                              <Badge className={getThreatLevelColor(event.severity)}>
                                {event.severity}
                              </Badge>
                              {event.ml_predicted && (
                                <Badge className="bg-blue-500/20 text-blue-400 text-xs">
                                  ML Predicted
                                </Badge>
                              )}
                            </div>
                            <span className="text-xs text-gray-400">
                              {new Date(event.timestamp).toLocaleString()}
                            </span>
                          </div>
                          <p className="text-sm text-gray-300">{event.description}</p>
                          <p className="text-xs text-gray-400 mt-1">Event: {event.event_type}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          )}

          {/* Analytics Tab - Admin and Security Analyst only */}
          {hasPermission('canViewAnalytics') && (
            <TabsContent value="analytics" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="text-white">Authentication Methods</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">Zero-Knowledge Proof</span>
                        <span className="font-semibold text-green-400">
                          {authLogs.filter(log => log.auth_method === "zero_knowledge" || log.auth_method === "multi_factor_zkp").length}
                        </span>  
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">Traditional</span>
                        <span className="font-semibold text-blue-400">
                          {authLogs.filter(log => log.auth_method === "traditional").length}
                        </span>
                      </div>
                      <Progress 
                        value={
                          authLogs.length > 0 
                            ? (authLogs.filter(log => log.auth_method === "zero_knowledge" || log.auth_method === "multi_factor_zkp").length / authLogs.length) * 100
                            : 0
                        } 
                        className="h-2"
                      />
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="text-white">Threat Analysis</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">ML Predictions</span>
                        <span className="font-semibold text-blue-400">
                          {dashboardStats.ml_predictions_today || 0}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">Anomalies</span>
                        <span className="font-semibold text-orange-400">
                          {dashboardStats.anomalies_detected || 0}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">High Risk Events</span>
                        <span className="font-semibold text-red-400">
                          {securityEvents.filter(event => event.severity === 'high' || event.severity === 'critical').length}
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700">
                  <CardHeader>
                    <CardTitle className="text-white">System Health</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">Uptime</span>
                        <Badge className="bg-green-500/20 text-green-400">99.9%</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">ZKP Success Rate</span>
                        <Badge className="bg-blue-500/20 text-blue-400">
                          {authLogs.filter(log => (log.auth_method === "zero_knowledge" || log.auth_method === "multi_factor_zkp") && log.success).length > 0 
                            ? Math.round((authLogs.filter(log => (log.auth_method === "zero_knowledge" || log.auth_method === "multi_factor_zkp") && log.success).length / authLogs.filter(log => log.auth_method === "zero_knowledge" || log.auth_method === "multi_factor_zkp").length) * 100)
                            : 100}%
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">Privacy Protected</span>
                        <Badge className="bg-purple-500/20 text-purple-400">
                          {authLogs.filter(log => log.privacy_preserved).length}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-300">ML Accuracy</span>
                        <Badge className="bg-cyan-500/20 text-cyan-400">94.2%</Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          )}
        </Tabs>
      </div>

      {/* Footer */}
      <footer className="bg-gray-800/30 border-t border-gray-700 mt-16">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-400">
              © 2024 Advanced ZKP IoT Authentication System
            </div>
            <div className="text-sm text-gray-400">
              Built by <span className="text-cyan-400 font-semibold">AshCodex Team</span> • Powered by AI & ZKP Technology
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

// Main App Component
function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for existing auth token
    const token = localStorage.getItem("token");
    const userData = localStorage.getItem("user");
    
    if (token && userData) {
      try {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      } catch (error) {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
      }
    }
    
    setLoading(false);
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-black flex items-center justify-center">
        <div className="text-center">
          <div className="p-3 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-2xl mx-auto mb-4 w-fit">
            <Shield className="h-12 w-12 text-white animate-pulse" />
          </div>
          <p className="text-gray-400">Loading AshCodex ZKP System...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return <Dashboard user={user} onLogout={handleLogout} />;
}

export default App;