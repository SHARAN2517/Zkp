from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import hashlib
import secrets
import json
from enum import Enum
import asyncio
import random

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="ZKP IoT Authentication System", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Enums
class DeviceType(str, Enum):
    SMART_HOME = "smart_home"
    HEALTHCARE = "healthcare"
    INDUSTRIAL = "industrial"
    WEARABLE = "wearable"
    SENSOR = "sensor"

class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    AUTHENTICATING = "authenticating"
    COMPROMISED = "compromised"

class AuthMethod(str, Enum):
    TRADITIONAL = "traditional"
    ZERO_KNOWLEDGE = "zero_knowledge"

class SensorType(str, Enum):
    TEMPERATURE = "temperature"
    HUMIDITY = "humidity"
    HEART_RATE = "heart_rate"
    MOTOR_TEMP = "motor_temperature"
    VIBRATION = "vibration"

# Data Models
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

class IoTDeviceCreate(BaseModel):
    device_name: str
    device_type: DeviceType
    manufacturer: str
    mac_address: str
    location: str

class SensorReading(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    sensor_type: SensorType
    value: float
    unit: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str = ""
    is_privacy_sensitive: bool = False

class ZKProof(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    proof_hash: str
    challenge: str
    response: str
    verifier_result: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
class AuthenticationLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    device_name: str
    auth_method: AuthMethod
    success: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: str = "127.0.0.1"
    risk_score: float = 0.0
    privacy_preserved: bool = True

class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    device_id: str
    severity: str  # low, medium, high, critical
    description: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False

class DashboardStats(BaseModel):
    total_devices: int
    online_devices: int
    successful_auths_today: int
    failed_auths_today: int
    avg_privacy_score: float
    threat_level: str
    total_sensor_readings: int
    privacy_sensitive_readings: int

class DataBatch(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_ids: List[str]
    merkle_root: str
    readings_count: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    blockchain_tx_hash: str = ""

# Helper Functions
def generate_zkp_identity_hash(device_name: str, mac_address: str) -> str:
    """Generate a unique identity hash for ZKP without revealing actual credentials"""
    combined = f"{device_name}:{mac_address}:{secrets.token_hex(16)}"
    return hashlib.sha256(combined.encode()).hexdigest()

def sign_sensor_data(device_id: str, sensor_type: str, value: float, timestamp: str) -> str:
    """Simulate signing of sensor data"""
    data_string = f"{device_id}:{sensor_type}:{value}:{timestamp}"
    return hashlib.sha256(data_string.encode()).hexdigest()

def simulate_zkp_proof(device_id: str, identity_hash: str) -> ZKProof:
    """Simulate Zero-Knowledge Proof generation and verification"""
    challenge = secrets.token_hex(32)
    # Simulate mathematical proof generation
    proof_data = f"{identity_hash}:{challenge}:{secrets.token_hex(16)}"
    proof_hash = hashlib.sha256(proof_data.encode()).hexdigest()
    response = hashlib.sha256(f"{proof_hash}:{challenge}".encode()).hexdigest()
    
    # Simulate verification (always true for demo, but would involve complex math)
    verifier_result = True
    
    return ZKProof(
        device_id=device_id,
        proof_hash=proof_hash,
        challenge=challenge,
        response=response,
        verifier_result=verifier_result
    )

def calculate_risk_score() -> float:
    """Calculate authentication risk score"""
    return round(random.uniform(0.1, 0.8), 2)

def simulate_sensor_reading(device: dict, sensor_type: SensorType) -> SensorReading:
    """Simulate realistic sensor readings based on device type and sensor"""
    
    # Define realistic ranges for different sensors
    sensor_configs = {
        SensorType.TEMPERATURE: {
            "smart_home": {"range": (18, 28), "unit": "°C"},
            "healthcare": {"range": (35, 42), "unit": "°C"},
            "industrial": {"range": (20, 80), "unit": "°C"},
            "default": {"range": (15, 35), "unit": "°C"}
        },
        SensorType.HUMIDITY: {
            "smart_home": {"range": (30, 70), "unit": "%"},
            "healthcare": {"range": (40, 60), "unit": "%"},
            "industrial": {"range": (20, 90), "unit": "%"},
            "default": {"range": (20, 80), "unit": "%"}
        },
        SensorType.HEART_RATE: {
            "healthcare": {"range": (60, 100), "unit": "bpm"},
            "wearable": {"range": (50, 180), "unit": "bpm"},
            "default": {"range": (60, 120), "unit": "bpm"}
        }
    }
    
    device_type = device.get('device_type', 'default')
    config = sensor_configs[sensor_type].get(device_type, sensor_configs[sensor_type]["default"])
    
    # Generate realistic value with some variation
    min_val, max_val = config["range"]
    value = round(random.uniform(min_val, max_val), 2)
    
    # Add some noise for realism
    noise = random.uniform(-0.5, 0.5)
    value += noise
    value = round(max(min_val, min(max_val, value)), 2)
    
    timestamp = datetime.now(timezone.utc)
    signature = sign_sensor_data(device['id'], sensor_type.value, value, timestamp.isoformat())
    
    # Heart rate is privacy sensitive
    is_privacy_sensitive = sensor_type == SensorType.HEART_RATE
    
    return SensorReading(
        device_id=device['id'],
        sensor_type=sensor_type,
        value=value,
        unit=config["unit"],
        timestamp=timestamp,
        signature=signature,
        is_privacy_sensitive=is_privacy_sensitive
    )

# Background task for IoT simulation
async def iot_simulation_background():
    """Background task to continuously generate IoT sensor data"""
    while True:
        try:
            devices = await db.devices.find({"status": "online"}).to_list(100)
            
            for device in devices:
                # Generate appropriate sensor readings based on device type
                readings_to_generate = []
                
                if device['device_type'] in ['smart_home', 'sensor']:
                    readings_to_generate.extend([SensorType.TEMPERATURE, SensorType.HUMIDITY])
                elif device['device_type'] in ['healthcare', 'wearable']:
                    readings_to_generate.extend([SensorType.HEART_RATE, SensorType.TEMPERATURE])
                elif device['device_type'] == 'industrial':
                    readings_to_generate.extend([SensorType.TEMPERATURE, SensorType.HUMIDITY])
                
                for sensor_type in readings_to_generate:
                    reading = simulate_sensor_reading(device, sensor_type)
                    reading_dict = reading.dict()
                    reading_dict['timestamp'] = reading_dict['timestamp'].isoformat()
                    await db.sensor_readings.insert_one(reading_dict)
            
            # Sleep for 10 seconds before next batch
            await asyncio.sleep(10)
            
        except Exception as e:
            logging.error(f"Error in IoT simulation: {e}")
            await asyncio.sleep(5)

# API Routes
@api_router.get("/")
async def root():
    return {"message": "ZKP IoT Authentication System API"}

@api_router.post("/devices", response_model=IoTDevice)
async def register_device(device_data: IoTDeviceCreate):
    """Register a new IoT device with ZKP identity"""
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
    
    # Log registration event
    event = SecurityEvent(
        event_type="device_registration",
        device_id=device.id,
        severity="low",
        description=f"New device {device.device_name} registered with ZKP authentication"
    )
    event_dict = event.dict()
    event_dict['timestamp'] = event_dict['timestamp'].isoformat()
    await db.security_events.insert_one(event_dict)
    
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

@api_router.post("/authenticate/{device_id}")
async def authenticate_device(device_id: str, auth_method: AuthMethod = AuthMethod.ZERO_KNOWLEDGE):
    """Authenticate device using specified method"""
    # Find device
    device_data = await db.devices.find_one({"id": device_id})
    if not device_data:
        raise HTTPException(status_code=404, detail="Device not found")
    
    success = True
    privacy_preserved = auth_method == AuthMethod.ZERO_KNOWLEDGE
    
    if auth_method == AuthMethod.ZERO_KNOWLEDGE:
        # Generate and verify ZKP
        zkp_proof = simulate_zkp_proof(device_id, device_data['zkp_identity_hash'])
        
        # Store proof
        proof_dict = zkp_proof.dict()
        proof_dict['timestamp'] = proof_dict['timestamp'].isoformat()
        await db.zkp_proofs.insert_one(proof_dict)
        
        success = zkp_proof.verifier_result
    
    # Create authentication log
    auth_log = AuthenticationLog(
        device_id=device_id,
        device_name=device_data['device_name'],
        auth_method=auth_method,
        success=success,
        risk_score=calculate_risk_score(),
        privacy_preserved=privacy_preserved
    )
    
    log_dict = auth_log.dict()
    log_dict['timestamp'] = log_dict['timestamp'].isoformat()
    await db.auth_logs.insert_one(log_dict)
    
    # Update device status
    await db.devices.update_one(
        {"id": device_id},
        {"$set": {"status": "online", "last_seen": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {
        "success": success,
        "auth_method": auth_method,
        "privacy_preserved": privacy_preserved,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@api_router.get("/sensor-readings/{device_id}")
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

@api_router.get("/authentication-logs", response_model=List[AuthenticationLog])
async def get_authentication_logs():
    """Get recent authentication logs"""
    logs = await db.auth_logs.find().sort("timestamp", -1).limit(100).to_list(100)
    result = []
    for log in logs:
        log['timestamp'] = datetime.fromisoformat(log['timestamp'])
        result.append(AuthenticationLog(**log))
    return result

@api_router.get("/security-events", response_model=List[SecurityEvent])
async def get_security_events():
    """Get recent security events"""
    events = await db.security_events.find().sort("timestamp", -1).limit(50).to_list(50)
    result = []
    for event in events:
        event['timestamp'] = datetime.fromisoformat(event['timestamp'])
        result.append(SecurityEvent(**event))
    return result

@api_router.get("/dashboard-stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get dashboard statistics"""
    total_devices = await db.devices.count_documents({})
    online_devices = await db.devices.count_documents({"status": "online"})
    
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
    
    # Calculate average privacy score
    privacy_logs = await db.auth_logs.find({"privacy_preserved": True}).to_list(1000)
    avg_privacy = len(privacy_logs) / max(total_devices, 1) * 100 if total_devices > 0 else 0
    
    # Count sensor readings
    total_sensor_readings = await db.sensor_readings.count_documents({})
    privacy_sensitive_readings = await db.sensor_readings.count_documents({"is_privacy_sensitive": True})
    
    # Determine threat level
    from datetime import timedelta
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
        successful_auths_today=successful_auths,
        failed_auths_today=failed_auths,
        avg_privacy_score=round(avg_privacy, 1),
        threat_level=threat_level,
        total_sensor_readings=total_sensor_readings,
        privacy_sensitive_readings=privacy_sensitive_readings
    )

@api_router.get("/simulate-threat")
async def simulate_threat():
    """Simulate a security threat for demonstration"""
    devices = await db.devices.find().to_list(10)
    if not devices:
        raise HTTPException(status_code=400, detail="No devices to simulate threat on")
    
    device = random.choice(devices)
    
    threat_types = [
        "unauthorized_access_attempt",
        "suspicious_authentication_pattern", 
        "potential_device_compromise",
        "anomalous_network_behavior",
        "privacy_breach_attempt",
        "sensor_tampering_detected"
    ]
    
    event = SecurityEvent(
        event_type=random.choice(threat_types),
        device_id=device['id'],
        severity=random.choice(["medium", "high"]),
        description=f"Simulated security event detected on {device['device_name']}"
    )
    
    event_dict = event.dict()
    event_dict['timestamp'] = event_dict['timestamp'].isoformat()
    await db.security_events.insert_one(event_dict)
    
    return {"message": "Threat simulation created", "event": event}

@api_router.post("/start-iot-simulation")
async def start_iot_simulation():
    """Start IoT sensor data simulation"""
    # This would start the background task in a real deployment
    return {"message": "IoT simulation started", "status": "running"}

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
    """Start background tasks"""
    # Start IoT simulation in background
    asyncio.create_task(iot_simulation_background())
    logger.info("IoT simulation background task started")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()