from fastapi import FastAPI, APIRouter, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import json
import asyncio
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
import uuid
from datetime import datetime, timezone, timedelta
import hashlib
import secrets
from enum import Enum
import random
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import aiofiles
import websockets
# import asyncio_mqtt as aiomqtt  # Commented out - will be implemented later
# import aioredis  # Commented out due to compatibility issues
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import plotly.graph_objects as go
import plotly.express as px
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="Advanced ZKP IoT Platform", version="2.0.0", description="Real-time IoT data processing with ML-based analytics and ZKP authentication")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Global variables for services
redis_client = None
mqtt_client = None
websocket_connections = []
ml_models = {}
alert_rules = {}

# Enhanced Enums
class DeviceType(str, Enum):
    SMART_HOME = "smart_home"
    HEALTHCARE = "healthcare"
    INDUSTRIAL = "industrial"
    WEARABLE = "wearable"
    SENSOR = "sensor"
    SECURITY = "security"
    ENVIRONMENTAL = "environmental"

class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    AUTHENTICATING = "authenticating"
    COMPROMISED = "compromised"
    MAINTENANCE = "maintenance"
    ERROR = "error"

class AuthMethod(str, Enum):
    TRADITIONAL = "traditional"
    ZERO_KNOWLEDGE = "zero_knowledge"

class SensorType(str, Enum):
    TEMPERATURE = "temperature"
    HUMIDITY = "humidity"
    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE = "blood_pressure"
    MOTION = "motion"
    LIGHT = "light"
    SOUND = "sound"
    AIR_QUALITY = "air_quality"
    PRESSURE = "pressure"
    VIBRATION = "vibration"
    GPS = "gps"
    BATTERY = "battery"

class DataSourceType(str, Enum):
    MQTT = "mqtt"
    WEBSOCKET = "websocket"
    REST_API = "rest_api"
    SIMULATED = "simulated"

class AlertType(str, Enum):
    ANOMALY = "anomaly"
    THRESHOLD = "threshold"
    SECURITY = "security"
    DEVICE_OFFLINE = "device_offline"
    PREDICTIVE = "predictive"

class ProcessingMode(str, Enum):
    STREAM = "stream"
    BATCH = "batch"
    HYBRID = "hybrid"

# Enhanced Data Models
class IoTDevice(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_name: str
    device_type: DeviceType
    manufacturer: str
    mac_address: str
    location: str
    status: DeviceStatus = DeviceStatus.OFFLINE
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    zkp_identity_hash: str = ""
    firmware_hash: str = Field(default_factory=lambda: hashlib.sha256(f"firmware_{secrets.token_hex(8)}".encode()).hexdigest())
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data_source: DataSourceType = DataSourceType.SIMULATED
    mqtt_topic: Optional[str] = None
    api_endpoint: Optional[str] = None
    connection_config: Dict[str, Any] = Field(default_factory=dict)
    capabilities: List[SensorType] = Field(default_factory=list)
    is_remote_controllable: bool = False
    geo_location: Optional[Dict[str, float]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class IoTDeviceCreate(BaseModel):
    device_name: str
    device_type: DeviceType
    manufacturer: str
    mac_address: str
    location: str
    data_source: DataSourceType = DataSourceType.SIMULATED
    mqtt_topic: Optional[str] = None
    api_endpoint: Optional[str] = None
    capabilities: List[SensorType] = Field(default_factory=list)
    is_remote_controllable: bool = False
    geo_location: Optional[Dict[str, float]] = None

class SensorReading(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    sensor_type: SensorType
    value: Union[float, str, Dict[str, Any]]
    unit: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str = ""
    is_privacy_sensitive: bool = False
    quality_score: float = 1.0
    anomaly_score: Optional[float] = None
    data_source: DataSourceType = DataSourceType.SIMULATED
    processing_metadata: Dict[str, Any] = Field(default_factory=dict)

class MLPrediction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    sensor_type: SensorType
    predicted_value: float
    confidence: float
    prediction_horizon: int  # minutes
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_version: str = "1.0"

class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    device_name: str
    alert_type: AlertType
    severity: str  # low, medium, high, critical
    title: str
    description: str
    value: Optional[Union[float, str]] = None
    threshold: Optional[float] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    actions_taken: List[str] = Field(default_factory=list)
    notification_sent: bool = False

class AlertRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: Optional[str] = None  # None means applies to all devices
    sensor_type: SensorType
    alert_type: AlertType
    conditions: Dict[str, Any]
    severity: str
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class DeviceCommand(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    command: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "pending"  # pending, sent, acknowledged, failed
    response: Optional[str] = None

class DashboardStats(BaseModel):
    total_devices: int
    online_devices: int
    offline_devices: int
    successful_auths_today: int
    failed_auths_today: int
    avg_privacy_score: float
    threat_level: str
    total_sensor_readings: int
    privacy_sensitive_readings: int
    alerts_today: int
    resolved_alerts_today: int
    ml_predictions_accuracy: float
    data_sources_active: Dict[str, int]
    processing_modes: Dict[str, int]

class DataProcessingConfig(BaseModel):
    device_id: str
    processing_mode: ProcessingMode
    batch_size: int = 100
    batch_interval: int = 60  # seconds
    stream_buffer_size: int = 1000
    enable_ml_predictions: bool = True
    enable_anomaly_detection: bool = True
    retention_days: int = 30

# Connection Manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

# ML Models and Analytics
class IoTAnalytics:
    def __init__(self):
        self.anomaly_models = {}
        self.prediction_models = {}
        self.scalers = {}

    async def train_anomaly_model(self, device_id: str, sensor_type: str, data: List[float]):
        """Train anomaly detection model for specific device and sensor"""
        if len(data) < 50:  # Need minimum data for training
            return None
        
        model = IsolationForest(contamination=0.1, random_state=42)
        scaler = StandardScaler()
        
        data_array = np.array(data).reshape(-1, 1)
        scaled_data = scaler.fit_transform(data_array)
        model.fit(scaled_data)
        
        model_key = f"{device_id}_{sensor_type}_anomaly"
        self.anomaly_models[model_key] = model
        self.scalers[model_key] = scaler
        
        # Save model to disk
        await self.save_model(model_key, model, scaler)
        return model

    async def detect_anomaly(self, device_id: str, sensor_type: str, value: float) -> float:
        """Detect anomaly for a sensor reading"""
        model_key = f"{device_id}_{sensor_type}_anomaly"
        
        if model_key not in self.anomaly_models:
            return 0.0  # No model trained yet
        
        model = self.anomaly_models[model_key]
        scaler = self.scalers[model_key]
        
        scaled_value = scaler.transform([[value]])
        anomaly_score = model.decision_function(scaled_value)[0]
        
        # Convert to 0-1 scale (higher = more anomalous)
        normalized_score = max(0, min(1, (0.5 - anomaly_score) * 2))
        return normalized_score

    async def save_model(self, model_key: str, model, scaler):
        """Save ML model to disk"""
        model_dir = Path("ml_models")
        model_dir.mkdir(exist_ok=True)
        
        joblib.dump(model, model_dir / f"{model_key}_model.pkl")
        joblib.dump(scaler, model_dir / f"{model_key}_scaler.pkl")

    async def load_models(self):
        """Load existing ML models from disk"""
        model_dir = Path("ml_models")
        if not model_dir.exists():
            return
        
        for model_file in model_dir.glob("*_model.pkl"):
            model_key = model_file.stem.replace("_model", "")
            scaler_file = model_dir / f"{model_key}_scaler.pkl"
            
            if scaler_file.exists():
                self.anomaly_models[model_key] = joblib.load(model_file)
                self.scalers[model_key] = joblib.load(scaler_file)

analytics = IoTAnalytics()

# Alert Management
class AlertManager:
    def __init__(self):
        self.notification_clients = {}
        self.setup_notification_clients()

    def setup_notification_clients(self):
        """Setup notification clients"""
        # Twilio for SMS
        if os.getenv('TWILIO_ACCOUNT_SID') and os.getenv('TWILIO_AUTH_TOKEN'):
            self.notification_clients['twilio'] = Client(
                os.getenv('TWILIO_ACCOUNT_SID'),
                os.getenv('TWILIO_AUTH_TOKEN')
            )
        
        # SendGrid for Email
        if os.getenv('SENDGRID_API_KEY'):
            self.notification_clients['sendgrid'] = SendGridAPIClient(
                api_key=os.getenv('SENDGRID_API_KEY')
            )

    async def evaluate_alert_rules(self, reading: SensorReading):
        """Evaluate all alert rules against a sensor reading"""
        alerts_triggered = []
        
        # Get applicable rules
        rules = await db.alert_rules.find({
            "$or": [
                {"device_id": reading.device_id},
                {"device_id": None}
            ],
            "sensor_type": reading.sensor_type.value,
            "enabled": True
        }).to_list(100)
        
        for rule_data in rules:
            rule = AlertRule(**rule_data)
            if await self.check_rule_condition(rule, reading):
                alert = await self.create_alert(rule, reading)
                alerts_triggered.append(alert)
                
                # Send notifications
                await self.send_notifications(alert)
        
        return alerts_triggered

    async def check_rule_condition(self, rule: AlertRule, reading: SensorReading) -> bool:
        """Check if alert rule condition is met"""
        conditions = rule.conditions
        value = float(reading.value) if isinstance(reading.value, (int, float)) else 0
        
        if rule.alert_type == AlertType.THRESHOLD:
            if "min_value" in conditions and value < conditions["min_value"]:
                return True
            if "max_value" in conditions and value > conditions["max_value"]:
                return True
        
        elif rule.alert_type == AlertType.ANOMALY:
            if reading.anomaly_score and reading.anomaly_score > conditions.get("anomaly_threshold", 0.8):
                return True
        
        return False

    async def create_alert(self, rule: AlertRule, reading: SensorReading) -> Alert:
        """Create and store alert"""
        device = await db.devices.find_one({"id": reading.device_id})
        device_name = device.get("device_name", "Unknown") if device else "Unknown"
        
        alert = Alert(
            device_id=reading.device_id,
            device_name=device_name,
            alert_type=rule.alert_type,
            severity=rule.severity,
            title=f"{rule.alert_type.value.title()} Alert - {reading.sensor_type.value}",
            description=f"Alert triggered for {device_name}: {reading.sensor_type.value} = {reading.value} {reading.unit}",
            value=reading.value,
            threshold=rule.conditions.get("max_value") or rule.conditions.get("min_value")
        )
        
        # Store alert
        alert_dict = alert.dict()
        alert_dict['timestamp'] = alert_dict['timestamp'].isoformat()
        await db.alerts.insert_one(alert_dict)
        
        return alert

    async def send_notifications(self, alert: Alert):
        """Send alert notifications"""
        # Broadcast to WebSocket connections
        await manager.broadcast(json.dumps({
            "type": "alert",
            "data": alert.dict(default=str)
        }))
        
        # TODO: Implement email/SMS notifications based on configuration
        # This would use the notification clients setup in setup_notification_clients()

alert_manager = AlertManager()

# Helper Functions
def generate_zkp_identity_hash(device_name: str, mac_address: str) -> str:
    """Generate a unique identity hash for ZKP without revealing actual credentials"""
    combined = f"{device_name}:{mac_address}:{secrets.token_hex(16)}"
    return hashlib.sha256(combined.encode()).hexdigest()

def sign_sensor_data(device_id: str, sensor_type: str, value: Union[float, str], timestamp: str) -> str:
    """Sign sensor data for integrity"""
    data_string = f"{device_id}:{sensor_type}:{value}:{timestamp}"
    return hashlib.sha256(data_string.encode()).hexdigest()

async def process_sensor_reading(reading: SensorReading, device: Dict[str, Any]):
    """Process sensor reading with ML analytics and alerts"""
    # Detect anomalies if enabled
    if isinstance(reading.value, (int, float)):
        anomaly_score = await analytics.detect_anomaly(
            reading.device_id, 
            reading.sensor_type.value, 
            float(reading.value)
        )
        reading.anomaly_score = anomaly_score
    
    # Store reading
    reading_dict = reading.dict()
    reading_dict['timestamp'] = reading_dict['timestamp'].isoformat()
    await db.sensor_readings.insert_one(reading_dict)
    
    # Evaluate alert rules
    alerts = await alert_manager.evaluate_alert_rules(reading)
    
    # Broadcast to WebSocket connections
    await manager.broadcast(json.dumps({
        "type": "sensor_reading",
        "data": reading_dict
    }))
    
    return reading, alerts

def simulate_realistic_sensor_data(device: dict, sensor_type: SensorType) -> SensorReading:
    """Enhanced simulation with more realistic patterns"""
    sensor_configs = {
        SensorType.TEMPERATURE: {
            "smart_home": {"range": (18, 28), "unit": "°C", "privacy": False},
            "healthcare": {"range": (35, 42), "unit": "°C", "privacy": True},
            "industrial": {"range": (20, 80), "unit": "°C", "privacy": False},
            "default": {"range": (15, 35), "unit": "°C", "privacy": False}
        },
        SensorType.HUMIDITY: {
            "smart_home": {"range": (30, 70), "unit": "%", "privacy": False},
            "healthcare": {"range": (40, 60), "unit": "%", "privacy": False},
            "industrial": {"range": (20, 90), "unit": "%", "privacy": False},
            "default": {"range": (20, 80), "unit": "%", "privacy": False}
        },
        SensorType.HEART_RATE: {
            "healthcare": {"range": (60, 100), "unit": "bpm", "privacy": True},
            "wearable": {"range": (50, 180), "unit": "bpm", "privacy": True},
            "default": {"range": (60, 120), "unit": "bpm", "privacy": True}
        },
        SensorType.BLOOD_PRESSURE: {
            "healthcare": {"range": (90, 140), "unit": "mmHg", "privacy": True},
            "wearable": {"range": (85, 150), "unit": "mmHg", "privacy": True},
            "default": {"range": (90, 140), "unit": "mmHg", "privacy": True}
        },
        SensorType.AIR_QUALITY: {
            "smart_home": {"range": (0, 500), "unit": "AQI", "privacy": False},
            "industrial": {"range": (0, 1000), "unit": "AQI", "privacy": False},
            "default": {"range": (0, 300), "unit": "AQI", "privacy": False}
        }
    }
    
    device_type = device.get('device_type', 'default')
    config = sensor_configs.get(sensor_type, {}).get(device_type)
    if not config:
        config = sensor_configs.get(sensor_type, {}).get("default", {"range": (0, 100), "unit": "units", "privacy": False})
    
    # Generate realistic value with temporal patterns
    min_val, max_val = config["range"]
    base_value = random.uniform(min_val, max_val)
    
    # Add some temporal variation (simulate daily/weekly patterns)
    current_hour = datetime.now().hour
    if sensor_type == SensorType.TEMPERATURE:
        # Temperature varies throughout the day
        daily_variation = 5 * np.sin(2 * np.pi * current_hour / 24)
        base_value += daily_variation
    
    # Add noise
    noise = random.uniform(-0.5, 0.5)
    value = round(max(min_val, min(max_val, base_value + noise)), 2)
    
    timestamp = datetime.now(timezone.utc)
    signature = sign_sensor_data(device['id'], sensor_type.value, value, timestamp.isoformat())
    
    return SensorReading(
        device_id=device['id'],
        sensor_type=sensor_type,
        value=value,
        unit=config["unit"],
        timestamp=timestamp,
        signature=signature,
        is_privacy_sensitive=config["privacy"],
        quality_score=random.uniform(0.9, 1.0),
        data_source=DataSourceType.SIMULATED
    )

# Background Tasks
async def iot_simulation_background():
    """Enhanced IoT simulation with ML model training"""
    training_counter = 0
    
    while True:
        try:
            devices = await db.devices.find({"status": "online"}).to_list(100)
            
            for device in devices:
                # Generate sensor readings based on device capabilities
                capabilities = device.get('capabilities', [])
                if not capabilities:
                    # Default capabilities based on device type
                    if device['device_type'] in ['smart_home', 'sensor']:
                        capabilities = [SensorType.TEMPERATURE.value, SensorType.HUMIDITY.value]
                    elif device['device_type'] in ['healthcare', 'wearable']:
                        capabilities = [SensorType.HEART_RATE.value, SensorType.TEMPERATURE.value, SensorType.BLOOD_PRESSURE.value]
                    elif device['device_type'] == 'industrial':
                        capabilities = [SensorType.TEMPERATURE.value, SensorType.VIBRATION.value, SensorType.PRESSURE.value]
                
                for sensor_type_str in capabilities:
                    try:
                        sensor_type = SensorType(sensor_type_str)
                        reading = simulate_realistic_sensor_data(device, sensor_type)
                        await process_sensor_reading(reading, device)
                    except ValueError:
                        continue  # Skip invalid sensor types
            
            # Train ML models periodically
            training_counter += 1
            if training_counter >= 60:  # Every 10 minutes (60 * 10 seconds)
                await train_ml_models_background()
                training_counter = 0
            
            await asyncio.sleep(10)
            
        except Exception as e:
            logging.error(f"Error in IoT simulation: {e}")
            await asyncio.sleep(5)

async def train_ml_models_background():
    """Train ML models with historical data"""
    try:
        devices = await db.devices.find().to_list(100)
        
        for device in devices:
            device_id = device['id']
            
            # Get historical data for each sensor type
            for sensor_type in [SensorType.TEMPERATURE, SensorType.HUMIDITY, SensorType.HEART_RATE]:
                readings = await db.sensor_readings.find({
                    "device_id": device_id,
                    "sensor_type": sensor_type.value
                }).sort("timestamp", -1).limit(1000).to_list(1000)
                
                if len(readings) >= 50:
                    values = [float(r['value']) for r in readings if isinstance(r['value'], (int, float))]
                    if values:
                        await analytics.train_anomaly_model(device_id, sensor_type.value, values)
        
        logging.info("ML models training completed")
        
    except Exception as e:
        logging.error(f"Error in ML model training: {e}")

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Advanced ZKP IoT Platform API", "version": "2.0.0"}

# WebSocket endpoint
@api_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo received data back to client
            await manager.send_personal_message(f"Message: {data}", websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@api_router.post("/devices", response_model=IoTDevice)
async def register_device(device_data: IoTDeviceCreate):
    """Register a new IoT device with enhanced capabilities"""
    # Generate ZKP identity hash
    zkp_hash = generate_zkp_identity_hash(device_data.device_name, device_data.mac_address)
    
    device = IoTDevice(
        **device_data.dict(),
        zkp_identity_hash=zkp_hash,
        status=DeviceStatus.ONLINE
    )
    
    # Store in database
    device_dict = device.dict()
    device_dict['last_seen'] = device_dict['last_seen'].isoformat()
    device_dict['created_at'] = device_dict['created_at'].isoformat()
    
    await db.devices.insert_one(device_dict)
    
    # Create processing configuration
    processing_config = DataProcessingConfig(
        device_id=device.id,
        processing_mode=ProcessingMode.HYBRID
    )
    config_dict = processing_config.dict()
    await db.processing_configs.insert_one(config_dict)
    
    return device

@api_router.get("/devices", response_model=List[IoTDevice])
async def get_devices():
    """Get all registered IoT devices"""
    devices = await db.devices.find().to_list(1000)
    result = []
    for device in devices:
        device['last_seen'] = datetime.fromisoformat(device['last_seen'])
        device['created_at'] = datetime.fromisoformat(device['created_at'])
        result.append(IoTDevice(**device))
    return result

@api_router.get("/devices/{device_id}/sensor-readings")
async def get_device_sensor_readings(device_id: str, limit: int = 50):
    """Get recent sensor readings for a specific device"""
    readings = await db.sensor_readings.find({"device_id": device_id}).sort("timestamp", -1).limit(limit).to_list(limit)
    result = []
    for reading in readings:
        reading['timestamp'] = datetime.fromisoformat(reading['timestamp'])
        result.append(SensorReading(**reading))
    return result

@api_router.get("/sensor-readings")
async def get_all_sensor_readings(limit: int = 100):
    """Get recent sensor readings from all devices"""
    readings = await db.sensor_readings.find().sort("timestamp", -1).limit(limit).to_list(limit)
    result = []
    for reading in readings:
        reading['timestamp'] = datetime.fromisoformat(reading['timestamp'])
        result.append(SensorReading(**reading))
    return result

@api_router.get("/alerts")
async def get_alerts(resolved: Optional[bool] = None):
    """Get alerts with optional filtering"""
    query = {}
    if resolved is not None:
        query["resolved"] = resolved
    
    alerts = await db.alerts.find(query).sort("timestamp", -1).limit(100).to_list(100)
    result = []
    for alert in alerts:
        alert['timestamp'] = datetime.fromisoformat(alert['timestamp'])
        if alert.get('resolved_at'):
            alert['resolved_at'] = datetime.fromisoformat(alert['resolved_at'])
        result.append(Alert(**alert))
    return result

@api_router.post("/devices/{device_id}/command")
async def send_device_command(device_id: str, command: str, parameters: Dict[str, Any] = None):
    """Send command to IoT device"""
    device = await db.devices.find_one({"id": device_id})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if not device.get("is_remote_controllable", False):
        raise HTTPException(status_code=400, detail="Device is not remote controllable")
    
    device_command = DeviceCommand(
        device_id=device_id,
        command=command,
        parameters=parameters or {}
    )
    
    command_dict = device_command.dict()
    command_dict['timestamp'] = command_dict['timestamp'].isoformat()
    await db.device_commands.insert_one(command_dict)
    
    # TODO: Implement actual device communication (MQTT, WebSocket, etc.)
    # For now, simulate command execution
    await asyncio.sleep(1)
    
    # Update command status
    await db.device_commands.update_one(
        {"id": device_command.id},
        {"$set": {"status": "sent", "response": "Command executed successfully"}}
    )
    
    return {"message": "Command sent successfully", "command_id": device_command.id}

@api_router.get("/dashboard-stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get comprehensive dashboard statistics"""
    total_devices = await db.devices.count_documents({})
    online_devices = await db.devices.count_documents({"status": "online"})
    offline_devices = await db.devices.count_documents({"status": "offline"})
    
    # Count today's authentications
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    successful_auths = await db.auth_logs.count_documents({
        "timestamp": {"$gte": today.isoformat()},
        "success": True
    })
    failed_auths = await db.auth_logs.count_documents({
        "timestamp": {"$gte": today.isoformat()},
        "success": False
    })
    
    # Calculate privacy score
    privacy_logs = await db.auth_logs.find({"privacy_preserved": True}).to_list(1000)
    avg_privacy = len(privacy_logs) / max(total_devices, 1) * 100 if total_devices > 0 else 0
    
    # Sensor readings
    total_sensor_readings = await db.sensor_readings.count_documents({})
    privacy_sensitive_readings = await db.sensor_readings.count_documents({"is_privacy_sensitive": True})
    
    # Alerts
    alerts_today = await db.alerts.count_documents({
        "timestamp": {"$gte": today.isoformat()}
    })
    resolved_alerts_today = await db.alerts.count_documents({
        "timestamp": {"$gte": today.isoformat()},
        "resolved": True
    })
    
    # Data sources
    data_sources = await db.devices.aggregate([
        {"$group": {"_id": "$data_source", "count": {"$sum": 1}}}
    ]).to_list(10)
    data_sources_active = {item["_id"]: item["count"] for item in data_sources}
    
    # Processing modes
    processing_modes = await db.processing_configs.aggregate([
        {"$group": {"_id": "$processing_mode", "count": {"$sum": 1}}}
    ]).to_list(10)
    processing_modes_dict = {item["_id"]: item["count"] for item in processing_modes}
    
    # Determine threat level
    recent_events = await db.security_events.find({
        "timestamp": {"$gte": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()}
    }).to_list(100)
    
    threat_level = "low"
    if len(recent_events) > 10:
        threat_level = "medium"
    if len(recent_events) > 25:
        threat_level = "high"
    
    return DashboardStats(
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        successful_auths_today=successful_auths,
        failed_auths_today=failed_auths,
        avg_privacy_score=round(avg_privacy, 1),
        threat_level=threat_level,
        total_sensor_readings=total_sensor_readings,
        privacy_sensitive_readings=privacy_sensitive_readings,
        alerts_today=alerts_today,
        resolved_alerts_today=resolved_alerts_today,
        ml_predictions_accuracy=95.0,  # TODO: Calculate from actual ML predictions
        data_sources_active=data_sources_active,
        processing_modes=processing_modes_dict
    )

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    """Start background tasks and initialize services"""
    # Load ML models
    await analytics.load_models()
    
    # Start IoT simulation in background
    asyncio.create_task(iot_simulation_background())
    
    logger.info("Advanced IoT platform started with ML analytics and real-time processing")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()