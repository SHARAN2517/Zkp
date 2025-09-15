import React, { useState, useEffect, useCallback, useMemo } from "react";
import "./App.css";
import axios from "axios";
import io from "socket.io-client";
import mqtt from "mqtt";
import { 
  Shield, Cpu, Activity, Lock, Users, AlertTriangle, CheckCircle, XCircle, 
  Eye, EyeOff, Thermometer, Heart, Zap, Wifi, WifiOff, Settings, 
  BarChart3, Brain, Bell, Play, Pause, RefreshCw, TrendingUp, 
  MapPin, Battery, Signal, Globe, Smartphone, Home, Building2,
  Wrench, AlertCircle, Send, Camera, Mic, Speaker, Monitor,
  Router, Layers, Database, Cloud, Server, MessageSquare
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Label } from "./components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./components/ui/select";
import { Badge } from "./components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { Alert, AlertDescription } from "./components/ui/alert";
import { Progress } from "./components/ui/progress";
import { Switch } from "./components/ui/switch";
import { Slider } from "./components/ui/slider";
import { Textarea } from "./components/ui/textarea";
import { 
  LineChart, Line, AreaChart, Area, BarChart, Bar, 
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  ScatterChart, Scatter, PieChart, Pie, Cell, RadialBarChart, RadialBar
} from "recharts";
import { ReactNotifications, Store } from "react-notifications-component";
import "react-notifications-component/dist/theme.css";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// WebSocket connection
let socket = null;
let mqttClient = null;

function App() {
  // State Management
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [sensorReadings, setSensorReadings] = useState([]);
  const [dashboardStats, setDashboardStats] = useState({});
  const [loading, setLoading] = useState(false);
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);
  const [connectionStatus, setConnectionStatus] = useState({
    websocket: 'disconnected',
    mqtt: 'disconnected',
    api: 'connected'
  });

  // Device Management
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [newDevice, setNewDevice] = useState({
    device_name: "",
    device_type: "smart_home",
    manufacturer: "",
    mac_address: "",
    location: "",
    data_source: "simulated",
    mqtt_topic: "",
    api_endpoint: "",
    capabilities: [],
    is_remote_controllable: false,
    geo_location: null
  });

  // Alert Configuration
  const [alertRules, setAlertRules] = useState([]);
  const [newAlertRule, setNewAlertRule] = useState({
    sensor_type: "temperature",
    alert_type: "threshold",
    conditions: { max_value: 30 },
    severity: "medium",
    enabled: true
  });

  // Real-time Data
  const [realtimeData, setRealtimeData] = useState({});
  const [anomalyDetection, setAnomalyDetection] = useState(true);
  const [mlPredictions, setMlPredictions] = useState([]);

  // Charts and Analytics
  const [chartTimeRange, setChartTimeRange] = useState('1h');
  const [selectedMetrics, setSelectedMetrics] = useState(['temperature', 'humidity']);

  // Device Commands
  const [deviceCommands, setDeviceCommands] = useState({});
  const [commandHistory, setCommandHistory] = useState([]);

  // Initialize connections
  useEffect(() => {
    initializeConnections();
    fetchAllData();
    
    const interval = setInterval(() => {
      if (!realTimeEnabled) {
        fetchAllData();
      }
    }, 30000); // Fallback polling every 30 seconds

    return () => {
      clearInterval(interval);
      if (socket) socket.disconnect();
      if (mqttClient) mqttClient.end();
    };
  }, [realTimeEnabled]);

  const initializeConnections = useCallback(() => {
    // WebSocket Connection
    if (!socket && realTimeEnabled) {
      const wsUrl = BACKEND_URL.replace('https://', 'wss://').replace('http://', 'ws://');
      socket = io(wsUrl, {
        transports: ['websocket', 'polling']
      });

      socket.on('connect', () => {
        setConnectionStatus(prev => ({ ...prev, websocket: 'connected' }));
        Store.addNotification({
          title: "WebSocket Connected",
          message: "Real-time data streaming enabled",
          type: "success",
          insert: "top",
          container: "top-right",
          animationIn: ["animate__animated", "animate__fadeIn"],
          animationOut: ["animate__animated", "animate__fadeOut"],
          dismiss: { duration: 3000 }
        });
      });

      socket.on('disconnect', () => {
        setConnectionStatus(prev => ({ ...prev, websocket: 'disconnected' }));
      });

      socket.on('sensor_reading', (data) => {
        handleRealtimeSensorData(data.data);
      });

      socket.on('alert', (data) => {
        handleRealtimeAlert(data.data);
      });

      socket.on('device_status', (data) => {
        handleDeviceStatusUpdate(data.data);
      });
    }

    // MQTT Connection (optional for direct device communication)
    if (!mqttClient && realTimeEnabled) {
      // In a real implementation, this would connect to an MQTT broker
      // For demo purposes, we'll simulate MQTT connection
      setConnectionStatus(prev => ({ ...prev, mqtt: 'simulated' }));
    }
  }, [realTimeEnabled]);

  const handleRealtimeSensorData = (reading) => {
    setSensorReadings(prev => {
      const updated = [reading, ...prev.slice(0, 99)]; // Keep last 100 readings
      return updated;
    });

    // Update real-time data for charts
    setRealtimeData(prev => {
      const deviceId = reading.device_id;
      const sensorType = reading.sensor_type;
      
      if (!prev[deviceId]) prev[deviceId] = {};
      if (!prev[deviceId][sensorType]) prev[deviceId][sensorType] = [];
      
      prev[deviceId][sensorType] = [
        ...prev[deviceId][sensorType].slice(-29), // Keep last 30 points
        {
          timestamp: new Date(reading.timestamp).getTime(),
          value: reading.value,
          anomaly_score: reading.anomaly_score || 0
        }
      ];
      
      return { ...prev };
    });

    // Show notification for anomalies
    if (reading.anomaly_score && reading.anomaly_score > 0.8) {
      Store.addNotification({
        title: "Anomaly Detected",
        message: `Unusual ${reading.sensor_type} reading: ${reading.value} ${reading.unit}`,
        type: "warning",
        insert: "top",
        container: "top-right",
        dismiss: { duration: 5000 }
      });
    }
  };

  const handleRealtimeAlert = (alert) => {
    setAlerts(prev => [alert, ...prev]);
    
    Store.addNotification({
      title: `${alert.severity.toUpperCase()} Alert`,
      message: alert.description,
      type: alert.severity === 'high' || alert.severity === 'critical' ? 'danger' : 'warning',
      insert: "top",
      container: "top-right",
      dismiss: { duration: 10000 }
    });
  };

  const handleDeviceStatusUpdate = (update) => {
    setDevices(prev => prev.map(device => 
      device.id === update.device_id 
        ? { ...device, status: update.status, last_seen: update.timestamp }
        : device
    ));
  };

  // Data fetching functions
  const fetchAllData = async () => {
    try {
      await Promise.all([
        fetchDevices(),
        fetchAlerts(),
        fetchSensorReadings(),
        fetchDashboardStats()
      ]);
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };

  const fetchDevices = async () => {
    try {
      const response = await axios.get(`${API}/devices`);
      setDevices(response.data);
    } catch (error) {
      console.error("Error fetching devices:", error);
    }
  };

  const fetchAlerts = async () => {
    try {
      const response = await axios.get(`${API}/alerts`);
      setAlerts(response.data);
    } catch (error) {
      console.error("Error fetching alerts:", error);
    }
  };

  const fetchSensorReadings = async () => {
    try {
      const response = await axios.get(`${API}/sensor-readings`);
      setSensorReadings(response.data);
    } catch (error) {
      console.error("Error fetching sensor readings:", error);
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
        location: "",
        data_source: "simulated",
        mqtt_topic: "",
        api_endpoint: "",
        capabilities: [],
        is_remote_controllable: false,
        geo_location: null
      });
      fetchAllData();
      
      Store.addNotification({
        title: "Device Registered",
        message: `${newDevice.device_name} has been successfully registered`,
        type: "success",
        insert: "top",
        container: "top-right",
        dismiss: { duration: 5000 }
      });
    } catch (error) {
      console.error("Error registering device:", error);
      Store.addNotification({
        title: "Registration Failed",
        message: "Failed to register device. Please try again.",
        type: "danger",
        insert: "top",
        container: "top-right",
        dismiss: { duration: 5000 }
      });
    }
    setLoading(false);
  };

  // Device Commands
  const sendDeviceCommand = async (deviceId, command, parameters = {}) => {
    try {
      const response = await axios.post(`${API}/devices/${deviceId}/command`, null, {
        params: { command },
        data: parameters
      });
      
      setCommandHistory(prev => [
        { deviceId, command, parameters, timestamp: new Date(), status: 'sent' },
        ...prev.slice(0, 49)
      ]);

      Store.addNotification({
        title: "Command Sent",
        message: `Command "${command}" sent to device`,
        type: "success",
        insert: "top",
        container: "top-right",
        dismiss: { duration: 3000 }
      });
    } catch (error) {
      console.error("Error sending command:", error);
      Store.addNotification({
        title: "Command Failed",
        message: "Failed to send command to device",
        type: "danger",
        insert: "top",
        container: "top-right",
        dismiss: { duration: 5000 }
      });
    }
  };

  // Utility functions
  const getStatusColor = (status) => {
    switch (status) {
      case "online": return "text-green-600 bg-green-50";
      case "offline": return "text-red-600 bg-red-50";
      case "authenticating": return "text-yellow-600 bg-yellow-50";
      case "compromised": return "text-red-800 bg-red-100";
      case "maintenance": return "text-blue-600 bg-blue-50";
      default: return "text-gray-600 bg-gray-50";
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "low": return "text-green-600 bg-green-50";
      case "medium": return "text-yellow-600 bg-yellow-50";
      case "high": return "text-orange-600 bg-orange-50";
      case "critical": return "text-red-600 bg-red-50";
      default: return "text-gray-600 bg-gray-50";
    }
  };

  const getDeviceIcon = (deviceType) => {
    switch (deviceType) {
      case "smart_home": return <Home className="h-5 w-5" />;
      case "healthcare": return <Heart className="h-5 w-5" />;
      case "industrial": return <Building2 className="h-5 w-5" />;
      case "wearable": return <Smartphone className="h-5 w-5" />;
      case "security": return <Shield className="h-5 w-5" />;
      case "environmental": return <Globe className="h-5 w-5" />;
      default: return <Cpu className="h-5 w-5" />;
    }
  };

  const getSensorIcon = (sensorType) => {
    switch (sensorType) {
      case "temperature": return <Thermometer className="h-4 w-4" />;
      case "heart_rate": return <Heart className="h-4 w-4" />;
      case "humidity": return <Activity className="h-4 w-4" />;
      case "motion": return <Activity className="h-4 w-4" />;
      case "light": return <Eye className="h-4 w-4" />;
      case "sound": return <Mic className="h-4 w-4" />;
      case "battery": return <Battery className="h-4 w-4" />;
      case "gps": return <MapPin className="h-4 w-4" />;
      default: return <Zap className="h-4 w-4" />;
    }
  };

  // Chart data processing
  const processChartData = useMemo(() => {
    if (!selectedDevice || !realtimeData[selectedDevice.id]) return [];
    
    const deviceData = realtimeData[selectedDevice.id];
    const combinedData = [];
    
    selectedMetrics.forEach(metric => {
      if (deviceData[metric]) {
        deviceData[metric].forEach(point => {
          const existingPoint = combinedData.find(p => p.timestamp === point.timestamp);
          if (existingPoint) {
            existingPoint[metric] = point.value;
            existingPoint[`${metric}_anomaly`] = point.anomaly_score;
          } else {
            combinedData.push({
              timestamp: point.timestamp,
              time: new Date(point.timestamp).toLocaleTimeString(),
              [metric]: point.value,
              [`${metric}_anomaly`]: point.anomaly_score
            });
          }
        });
      }
    });
    
    return combinedData.sort((a, b) => a.timestamp - b.timestamp);
  }, [selectedDevice, realtimeData, selectedMetrics]);

  const connectionStatusColor = (status) => {
    switch (status) {
      case 'connected': return 'text-green-600';
      case 'simulated': return 'text-blue-600';
      case 'disconnected': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      <ReactNotifications />
      
      {/* Enhanced Header */}
      <header className="bg-white/80 backdrop-blur-md border-b border-slate-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-xl">
                <Shield className="h-8 w-8 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-slate-900">Advanced ZKP IoT Platform</h1>
                <p className="text-slate-600 text-sm">Real-time Analytics • ML-Powered • Secure</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              {/* Connection Status */}
              <div className="flex items-center space-x-2 text-sm">
                <div className="flex items-center space-x-1">
                  <Wifi className={`h-4 w-4 ${connectionStatusColor(connectionStatus.websocket)}`} />
                  <span className={connectionStatusColor(connectionStatus.websocket)}>WS</span>
                </div>
                <div className="flex items-center space-x-1">
                  <Router className={`h-4 w-4 ${connectionStatusColor(connectionStatus.mqtt)}`} />
                  <span className={connectionStatusColor(connectionStatus.mqtt)}>MQTT</span>
                </div>
                <div className="flex items-center space-x-1">
                  <Server className={`h-4 w-4 ${connectionStatusColor(connectionStatus.api)}`} />
                  <span className={connectionStatusColor(connectionStatus.api)}>API</span>
                </div>
              </div>

              {/* Real-time Toggle */}
              <div className="flex items-center space-x-2">
                <Label htmlFor="realtime" className="text-sm font-medium">Real-time</Label>
                <Switch
                  id="realtime"
                  checked={realTimeEnabled}
                  onCheckedChange={setRealTimeEnabled}
                />
              </div>

              {/* Action Buttons */}
              <Button onClick={fetchAllData} variant="outline" className="hover:bg-blue-50">
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Enhanced Dashboard Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-6 mb-8">
          <Card className="bg-white/60 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-slate-600">Total Devices</CardTitle>
              <Cpu className="h-4 w-4 text-slate-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-slate-900">{dashboardStats.total_devices || 0}</div>
              <p className="text-xs text-slate-500">
                <span className="text-green-600">{dashboardStats.online_devices || 0}</span> online • 
                <span className="text-red-600 ml-1">{dashboardStats.offline_devices || 0}</span> offline
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white/60 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-slate-600">Active Alerts</CardTitle>
              <AlertTriangle className="h-4 w-4 text-orange-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-600">{alerts.filter(a => !a.resolved).length}</div>
              <p className="text-xs text-slate-500">
                {dashboardStats.resolved_alerts_today || 0} resolved today
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white/60 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-slate-600">ML Accuracy</CardTitle>
              <Brain className="h-4 w-4 text-purple-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-600">{dashboardStats.ml_predictions_accuracy || 95}%</div>
              <Progress value={dashboardStats.ml_predictions_accuracy || 95} className="mt-2 h-2" />
            </CardContent>
          </Card>

          <Card className="bg-white/60 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-slate-600">Data Streams</CardTitle>
              <Activity className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{dashboardStats.total_sensor_readings || 0}</div>
              <p className="text-xs text-slate-500">
                {dashboardStats.privacy_sensitive_readings || 0} private
              </p>
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
              <Shield className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <Badge className={getSeverityColor(dashboardStats.threat_level || 'low')}>
                {(dashboardStats.threat_level || 'low').toUpperCase()}
              </Badge>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="dashboard" className="space-y-6">
          <TabsList className="grid w-full grid-cols-7 bg-white/60 backdrop-blur-sm">
            <TabsTrigger value="dashboard">Real-time Dashboard</TabsTrigger>
            <TabsTrigger value="devices">Device Management</TabsTrigger>
            <TabsTrigger value="analytics">ML Analytics</TabsTrigger>
            <TabsTrigger value="alerts">Alert Management</TabsTrigger>
            <TabsTrigger value="control">Device Control</TabsTrigger>
            <TabsTrigger value="data">Data Sources</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
          </TabsList>

          {/* Real-time Dashboard */}
          <TabsContent value="dashboard" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Device Selection */}
              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Select Device for Analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  <Select 
                    onValueChange={(deviceId) => {
                      const device = devices.find(d => d.id === deviceId);
                      setSelectedDevice(device);
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Choose a device..." />
                    </SelectTrigger>
                    <SelectContent>
                      {devices.map(device => (
                        <SelectItem key={device.id} value={device.id}>
                          <div className="flex items-center space-x-2">
                            {getDeviceIcon(device.device_type)}
                            <span>{device.device_name}</span>
                            <Badge className={getStatusColor(device.status)}>
                              {device.status}
                            </Badge>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  {selectedDevice && (
                    <div className="mt-4 space-y-2">
                      <h4 className="font-semibold">Metrics to Display:</h4>
                      <div className="space-y-2">
                        {selectedDevice.capabilities?.map(capability => (
                          <div key={capability} className="flex items-center space-x-2">
                            <Switch
                              checked={selectedMetrics.includes(capability)}
                              onCheckedChange={(checked) => {
                                if (checked) {
                                  setSelectedMetrics(prev => [...prev, capability]);
                                } else {
                                  setSelectedMetrics(prev => prev.filter(m => m !== capability));
                                }
                              }}
                            />
                            <Label>{capability.replace('_', ' ').toUpperCase()}</Label>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Real-time Chart */}
              <Card className="lg:col-span-2 bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Real-time Sensor Data</CardTitle>
                  <CardDescription>
                    {selectedDevice ? `Monitoring ${selectedDevice.device_name}` : 'Select a device to view data'}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {selectedDevice && processChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={400}>
                      <LineChart data={processChartData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis />
                        <Tooltip />
                        {selectedMetrics.map((metric, index) => (
                          <Line 
                            key={metric}
                            type="monotone" 
                            dataKey={metric} 
                            stroke={['#8884d8', '#82ca9d', '#ffc658', '#ff7300'][index % 4]}
                            strokeWidth={2}
                            dot={{ r: 4 }}
                          />
                        ))}
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex items-center justify-center h-64 text-slate-400">
                      <div className="text-center">
                        <Activity className="h-12 w-12 mx-auto mb-2" />
                        <p>No real-time data available</p>
                        <p className="text-sm">Select a device to start monitoring</p>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Recent Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Live Sensor Readings */}
              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Activity className="h-5 w-5 mr-2" />
                    Live Sensor Data Stream
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {sensorReadings.slice(0, 10).map((reading, index) => (
                      <div key={`${reading.id}-${index}`} className="flex items-center justify-between p-3 border border-slate-200 rounded-lg bg-white/50">
                        <div className="flex items-center space-x-3">
                          <div className="p-2 rounded-lg bg-blue-50">
                            {getSensorIcon(reading.sensor_type)}
                          </div>
                          <div>
                            <p className="font-medium text-slate-900">
                              {reading.value} {reading.unit}
                            </p>
                            <p className="text-xs text-slate-500">
                              {reading.sensor_type} • {new Date(reading.timestamp).toLocaleTimeString()}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          {reading.anomaly_score > 0.8 && (
                            <Badge className="bg-red-100 text-red-800 text-xs">
                              Anomaly
                            </Badge>
                          )}
                          {reading.is_privacy_sensitive && (
                            <Badge className="bg-purple-100 text-purple-800 text-xs">
                              Private
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Recent Alerts */}
              <Card className="bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Bell className="h-5 w-5 mr-2" />
                    Recent Alerts
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {alerts.slice(0, 10).map((alert) => (
                      <div key={alert.id} className="p-3 border border-slate-200 rounded-lg bg-white/50">
                        <div className="flex items-center justify-between mb-2">
                          <Badge className={getSeverityColor(alert.severity)}>
                            {alert.severity.toUpperCase()}
                          </Badge>
                          <span className="text-xs text-slate-500">
                            {new Date(alert.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <h4 className="font-semibold text-slate-900">{alert.title}</h4>
                        <p className="text-sm text-slate-700 mt-1">{alert.description}</p>
                        {!alert.resolved && (
                          <Button size="sm" variant="outline" className="mt-2">
                            Resolve
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Enhanced Device Management remains similar but with additional capabilities */}
          <TabsContent value="devices" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Enhanced Device Registration Form */}
              <Card className="lg:col-span-1 bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Users className="h-5 w-5 mr-2" />
                    Register IoT Device
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <form onSubmit={registerDevice} className="space-y-4">
                    <div>
                      <Label htmlFor="device_name">Device Name</Label>
                      <Input
                        id="device_name"
                        value={newDevice.device_name}
                        onChange={(e) => setNewDevice({...newDevice, device_name: e.target.value})}
                        placeholder="Smart Temperature Sensor"
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
                          <SelectItem value="security">Security</SelectItem>
                          <SelectItem value="environmental">Environmental</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label htmlFor="data_source">Data Source</Label>
                      <Select 
                        value={newDevice.data_source} 
                        onValueChange={(value) => setNewDevice({...newDevice, data_source: value})}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="simulated">Simulated</SelectItem>
                          <SelectItem value="mqtt">MQTT</SelectItem>
                          <SelectItem value="websocket">WebSocket</SelectItem>
                          <SelectItem value="rest_api">REST API</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    {newDevice.data_source === "mqtt" && (
                      <div>
                        <Label htmlFor="mqtt_topic">MQTT Topic</Label>
                        <Input
                          id="mqtt_topic"
                          value={newDevice.mqtt_topic}
                          onChange={(e) => setNewDevice({...newDevice, mqtt_topic: e.target.value})}
                          placeholder="sensors/temperature/01"
                        />
                      </div>
                    )}

                    <div>
                      <Label htmlFor="manufacturer">Manufacturer</Label>
                      <Input
                        id="manufacturer"
                        value={newDevice.manufacturer}
                        onChange={(e) => setNewDevice({...newDevice, manufacturer: e.target.value})}
                        placeholder="TechCorp Inc."
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

                    <div className="flex items-center space-x-2">
                      <Switch
                        checked={newDevice.is_remote_controllable}
                        onCheckedChange={(checked) => setNewDevice({...newDevice, is_remote_controllable: checked})}
                      />
                      <Label>Remote Controllable</Label>
                    </div>

                    <Button type="submit" disabled={loading} className="w-full">
                      {loading ? "Registering..." : "Register Device"}
                    </Button>
                  </form>
                </CardContent>
              </Card>

              {/* Enhanced Device List */}
              <Card className="lg:col-span-2 bg-white/70 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Registered Devices</CardTitle>
                  <CardDescription>
                    {devices.length} devices • {devices.filter(d => d.status === 'online').length} online
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {devices.map((device) => (
                      <div key={device.id} className="flex items-center justify-between p-4 border border-slate-200 rounded-lg bg-white/50">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3">
                            {getDeviceIcon(device.device_type)}
                            <div>
                              <div className="flex items-center space-x-2">
                                <h3 className="font-semibold text-slate-900">{device.device_name}</h3>
                                <Badge className={getStatusColor(device.status)}>
                                  {device.status}
                                </Badge>
                                <Badge variant="outline">
                                  {device.data_source}
                                </Badge>
                              </div>
                              <p className="text-sm text-slate-600">{device.manufacturer} • {device.location}</p>
                              <p className="text-xs text-slate-500">
                                MAC: {device.mac_address} • 
                                Last seen: {new Date(device.last_seen).toLocaleString()}
                              </p>
                            </div>
                          </div>
                        </div>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            onClick={() => setSelectedDevice(device)}
                            variant="outline"
                          >
                            <BarChart3 className="h-4 w-4 mr-1" />
                            Analyze
                          </Button>
                          {device.is_remote_controllable && (
                            <Button
                              size="sm"
                              onClick={() => {/* Open control panel */}}
                              className="bg-blue-600 hover:bg-blue-700"
                            >
                              <Settings className="h-4 w-4 mr-1" />
                              Control
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Other tabs would continue with similar enhancements... */}
          {/* For brevity, I'll include just the structure for the remaining tabs */}
          
          <TabsContent value="analytics">
            <Card className="bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Machine Learning Analytics</CardTitle>
                <CardDescription>Advanced analytics and predictive insights</CardDescription>
              </CardHeader>
              <CardContent>
                <p>ML Analytics features coming soon...</p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="alerts">
            <Card className="bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Alert Management</CardTitle>
                <CardDescription>Configure and manage alert rules</CardDescription>
              </CardHeader>
              <CardContent>
                <p>Alert management features coming soon...</p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="control">
            <Card className="bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Device Control Center</CardTitle>
                <CardDescription>Remote device management and control</CardDescription>
              </CardHeader>
              <CardContent>
                <p>Device control features coming soon...</p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="data">
            <Card className="bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Data Source Management</CardTitle>
                <CardDescription>Configure MQTT, WebSocket, and API connections</CardDescription>
              </CardHeader>
              <CardContent>
                <p>Data source configuration coming soon...</p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="settings">
            <Card className="bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Platform Settings</CardTitle>
                <CardDescription>Configure platform behavior and preferences</CardDescription>
              </CardHeader>
              <CardContent>
                <p>Settings panel coming soon...</p>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

export default App;